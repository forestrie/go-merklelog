package massifs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	commoncbor "github.com/datatrails/go-datatrails-common/cbor"
	"github.com/datatrails/go-datatrails-merklelog/massifs/storage"
	"github.com/datatrails/go-datatrails-merklelog/mmr"
	"github.com/veraison/go-cose"
)

var (
	ErrSourceLogTruncated             = errors.New("the local replica indicates the remote log has been truncated")
	ErrSourceLogInconsistentRootState = errors.New("the local replica root state disagrees with the remote")
)

// ReplaceVerifiedContext stores the massif data and its associated checkpoint message
// into the provided ObjectWriter. It first writes the massif data, then marshals
// and writes the checkpoint message as CBOR. If any operation fails, an error is returned.
//
// Parameters:
//
//	ctx - the context for controlling cancellation and deadlines
//	objectWriter - the writer interface used to store massif data and checkpoint
//	vc - the VerifiedContext containing the massif data and checkpoint message
//
// Returns:
//
//	error - non-nil if storing data or marshaling the checkpoint fails
func ReplaceVerifiedContext(ctx context.Context, objectWriter ObjectWriter, vc *VerifiedContext) error {
	var err error

	// put the data first, a racy seal read will still be valid
	err = objectWriter.Put(ctx, vc.MassifContext.Start.MassifIndex, storage.ObjectMassifData, vc.MassifContext.Data, false)
	if err != nil {
		return fmt.Errorf("failed to store massif data: %w", err)
	}

	data, err := vc.Sign1Message.MarshalCBOR()
	if err != nil {
		return fmt.Errorf("failed to marshal checkpoint message: %w", err)
	}

	return objectWriter.Put(ctx, vc.MassifContext.Start.MassifIndex, storage.ObjectCheckpoint, data, false)
}

type VerifyingReplicator struct {
	CBORCodec    commoncbor.CBORCodec
	COSEVerifier cose.Verifier

	// Source provides the upstream (source of truth) log to replicate from.
	Source ObjectReader
	// Sink is the downstream replica where the log is replicated to.
	Sink ObjectReaderWriter
}

// ReplicateVerifiedUpdates replicates and verifies massif updates from the source to the sink
//
// within the specified massif index range [startMassif, endMassif]. It ensures that the sink
// replica is consistent with the source by verifying the integrity of each massif and its seal.
// The function promotes legacy (v0) massif states to the current (v1) format as needed for
// compatibility and consistency checks. If a massif is missing or outdated in the sink, it is
// copied from the source after verification. The process skips massifs that have already been
// verified and replicated in the sink. Returns an error if verification or replication fails at
// any step.
//
// Parameters:
//
//	ctx         - Context for cancellation and deadlines.
//	startMassif - The starting massif index to replicate (inclusive).
//	endMassif   - The ending massif index to replicate (inclusive).
//
// Returns:
//
//	error - Non-nil if verification or replication fails.
func (v *VerifyingReplicator) ReplicateVerifiedUpdates(
	ctx context.Context,
	startMassif, endMassif uint32,
) error {
	isNilOrNotFound := func(err error) bool {
		if err == nil {
			return true
		}
		if errors.Is(err, storage.ErrDoesNotExist) {
			return true
		}

		if errors.Is(err, storage.ErrLogEmpty) {
			return true
		}

		// SelectLog on the sink reader always primes the cache. So NotAvailable is equivalent to not found.
		if errors.Is(err, storage.ErrNotAvailable) {
			return true
		}

		return false
	}

	// on demand promotion of a v0 state to a v1 state, for compatibility with the consistency check.
	trustedBaseState := func(sink *VerifiedContext) (MMRState, error) {
		if sink.MMRState.Version > int(MMRStateVersion0) {
			return sink.MMRState, nil
		}

		// At this point we have a sink seal in v0 format and we expect the
		// source seal to be in v1 format.
		// We need to promote the legacy base state to a V1 state for the
		// consistency check.  This is a one way operation, and the legacy seal
		// root is discarded.  Once the seal for the open massif is upgraded,
		// this case will never be encountered again for that tenant.

		peaks, err := mmr.PeakHashes(sink, sink.MMRState.MMRSize-1)
		if err != nil {
			return MMRState{}, err
		}
		root := mmr.HashPeaksRHS(sha256.New(), peaks)
		if !bytes.Equal(root, sink.MMRState.LegacySealRoot) {
			return MMRState{}, fmt.Errorf("legacy seal root does not match the bagged peaks")
		}
		state := sink.MMRState
		state.Version = int(MMRStateVersion1)
		// Keep the legacy seal root so that we can verify in the case where the source is a V0 seal
		// state.LegacySealRoot = nil
		state.Peaks = peaks
		return state, nil
	}

	// if err := v.Sink.SelectLog(ctx, logID); err != nil {
	// 	return fmt.Errorf("failed to select sink log %s: %w", logID, err)
	// }

	// if err := v.Source.SelectLog(ctx, logID); err != nil {
	// 	return fmt.Errorf("failed to select source log %s: %w", logID, err)
	// }

	// Read the most recently verified state from the sink store. The
	// verification ensures the sink replica has not been corrupted, but this
	// check trusts the seal stored locally with the head massif
	sinkHeadCheckpointIndex, err := v.Sink.HeadIndex(ctx, storage.ObjectCheckpoint)
	if err != nil {
		return err
	}

	sink, err := GetContextVerified(
		ctx, v.Sink, &v.CBORCodec, v.COSEVerifier, sinkHeadCheckpointIndex)
	if !isNilOrNotFound(err) {
		return err
	}

	// We always verify up to the requested massif, but we do not re-verify
	// massifs we have already verified and replicated in the sink. If the last
	// sink-replicated massif is ahead of the endMassif we do nothing here.
	//
	// The --ancestors option is used to ensure there is a minimum number of
	// verified massifs replicated in the sink, and influences the startMassif to
	// achieve this.
	//
	// The startMassif is the greater of the requested start and the massif
	// index of the last sink-verified massif.  Our verification always reads
	// the source massifs starting from the startMassif.
	//
	// In the loop below we ensure three key things:
	// 1. If there is a sink replica of the source, we ensure the source is
	//    consistent with the replica.
	// 2. If the source starts a new massif, and we have its
	//    predecessor in the sink, we ensure the source is consistent with the sink predecessor.
	// 3. If there is no sink replica, we create one by copying the source.
	//
	// Note that we arrange things so that sink is always the last available
	// sink massif, or nil.  When dealing with the source corresponding to
	// startMassif, the sink is *either* the predecessor or is the incomplete
	// sink replica of the source being considered. After the first source is
	// dealt with, sink is always the predecessor.

	if sink != nil {
		// Start from the next massif after the last verified massif and do not
		// re-verify massifs we have already verified and replicated in the sink,
		if startMassif > sink.Start.MassifIndex+1 {
			// if the start of the ancestors is more than one massif ahead of
			// the sink, then we start afresh.
			sink = nil
		} else {
			startMassif = sink.Start.MassifIndex
		}
	}

	for i := startMassif; i <= endMassif; i++ {

		// Note: we have to fetch the seal before the massif, otherwise we can lose a race with the builder
		// See bug#10530
		checkpt, err := GetCheckpoint(ctx, v.Source, v.CBORCodec, i)
		if err != nil {
			return err
		}

		sourceOpts := []Option{WithVerifyCheckpoint(&checkpt)}
		if sink != nil {
			var baseState MMRState
			// Promote the trusted base state to a V1 state if it is a V0 state.
			baseState, err = trustedBaseState(sink)
			if err != nil {
				return err
			}
			sourceOpts = append(sourceOpts, WithVerifyTrustedState(baseState))
		}

		// On the first iteration sink is *either* the predecessor to
		// startMassif or it is the, as yet, incomplete sink replica of it.
		// After the first iteration, sink is always the predecessor. (If the
		// source is still incomplete it means there is no subsequent massif to
		// read)
		source, err := GetContextVerified(
			ctx, v.Source, &v.CBORCodec, v.COSEVerifier, i, sourceOpts...)
		if err != nil {
			// both the source massif and its seal must be present for the
			// verification to succeed, so we don't filter using isBlobNotFound
			// here.
			return err
		}

		// read the sink massif, if it exists, reading at the end of the loop
		sink, err = GetContextVerified(ctx, v.Sink, &v.CBORCodec, v.COSEVerifier, i)
		if !isNilOrNotFound(err) {
			return err
		}

		// copy the source locally to the sink, safely replacing the corresponding sink if
		// one exists. if the sink is replaced (or created) without error, the
		// source verified context becomes the new sink.
		sink, err = v.replicateVerifiedContext(ctx, sink, source)
		if err != nil {
			return err
		}
	}

	return nil
}

// replicateVerifiedContext is used to replicate a source massif which may be an
// extension of a previously verified sink copy.
//
// If sink is nil, this method simply replicates the verified source unconditionally.
//
// Otherwise, sink and source are required to be the same tenant and the same massif.
// This method then deals with ensuring the source is a consistent extension of
// sink before replacing the previously verified sink.
//
// This method has no side effects in the case where the source and the sink are
// verified to be identical, the original sink instance is retained.
// replicateVerifiedContext synchronizes the state between a sink and a source
// VerifiedContext.  If the sink is nil, it replaces the sink with the source's
// state. Otherwise, it checks that both contexts refer to the same massif index
// and that the source log has not been truncated.  If the sink and source have
// the same length, it verifies their states are equal. If the source has new
// data, it replaces the sink's state with the source's. Returns the updated
// VerifiedContext or an error if consistency checks fail.
func (v *VerifyingReplicator) replicateVerifiedContext(
	ctx context.Context,
	sink *VerifiedContext, source *VerifiedContext,
) (*VerifiedContext, error) {
	if sink == nil {
		return nil, ReplaceVerifiedContext(ctx, v.Sink, source)
	}

	// We rely exclusively on consistency checks to ensure we don't append the
	// source state to the sink replica for a different log.

	if sink.Start.MassifIndex != source.Start.MassifIndex {
		return nil, fmt.Errorf(
			"can't replace, massif indices don't match: sink %d vs source %d",
			sink.Start.MassifIndex, source.Start.MassifIndex)
	}

	massifIndex := sink.Start.MassifIndex

	if len(sink.Data) > len(source.Data) {
		// the source log has been truncated since we last looked
		return nil, fmt.Errorf("%w: massif=%d", ErrSourceLogTruncated, massifIndex)
	}

	// if the source and sink are the same, we are done, provided the roots still match
	if len(sink.Data) == len(source.Data) {
		// note: the length equal check is elevated so we only write to sink if
		// there are changes.  this duplicates a check in verifiedStateEqual in
		// the interest of avoiding accidents due to future refactorings.
		if !verifiedStateEqual(sink, source) {
			return nil, fmt.Errorf("%w: massif=%d", ErrSourceLogInconsistentRootState, massifIndex)
		}
		return sink, nil
	}

	err := ReplaceVerifiedContext(ctx, v.Sink, source)
	if err != nil {
		return nil, err
	}

	// We have successfully replaced the sink data with the data from the source. The
	// source vc is now equivalent to the sink
	return source, nil
}

func verifiedStateEqual(a *VerifiedContext, b *VerifiedContext) bool {
	var err error

	// There is no difference in the log format between the two versions currently supported.
	if len(a.Data) != len(b.Data) {
		return false
	}
	fromRoots := a.ConsistentRoots
	toRoots := b.ConsistentRoots
	// If either state is a V0 state, compare the legacy seal roots
	if a.MMRState.Version == int(MMRStateVersion0) || b.MMRState.Version == int(MMRStateVersion0) {
		rootA := peakBaggedRoot(a.MMRState)
		rootB := peakBaggedRoot(b.MMRState)
		if !bytes.Equal(rootA, rootB) {
			return false
		}
		if a.MMRState.Version == int(MMRStateVersion0) {
			fromRoots, err = mmr.PeakHashes(a, a.MMRState.MMRSize-1)
			if err != nil {
				return false
			}
		}
		if b.MMRState.Version == int(MMRStateVersion0) {
			toRoots, err = mmr.PeakHashes(b, b.MMRState.MMRSize-1)
			if err != nil {
				return false
			}
		}

	}

	// If both states are V1 states, compare the peaks
	if len(fromRoots) != len(toRoots) {
		return false
	}
	for i := range len(fromRoots) {
		if !bytes.Equal(fromRoots[i], toRoots[i]) {
			return false
		}
	}
	return true
}

// peakBaggedRoot is used to obtain an MMRState V0 bagged root from a V1 accumulator peak list.
// If a v0 state is provided, the root is returned as is.
func peakBaggedRoot(state MMRState) []byte {
	if state.Version < int(MMRStateVersion1) {
		return state.LegacySealRoot
	}
	return mmr.HashPeaksRHS(sha256.New(), state.Peaks)
}
