package massifs

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/forestrie/go-merklelog/mmr"
)

// VerifiedContext is a MassifContext whose data has been verified against its
// sealed checkpoint (a format-v3 consistency receipt, ADR-0046).
type VerifiedContext struct {
	MassifContext

	// Checkpoint is the checkpoint the massif data was verified against. For
	// a verified context it is guaranteed to refer to the portion of the log
	// identified by the massif index, but the committed data may extend past
	// the data confirmed by the seal.
	Checkpoint

	// Accumulator is the verified accumulator (peak hashes) for the sealed
	// MMRSize: it is read from the massif data and the checkpoint receipt
	// signature verifies over its detached payload.
	Accumulator [][]byte

	// ConsistentRoots is the accumulator for the entire range of the massif
	// context data, verified as consistent with the sealed accumulator. The
	// committed data may extend past the seal, in which case these differ
	// from Accumulator.
	ConsistentRoots [][]byte
}

// VerifyContext verifies the log data in the context is consistent with its
// checkpoint, and optionally also checks consistency against a trusted base
// state provided from a trusted source.
// Returns:
//   - a VerifiedContext which references the dynamically allocated aspects of this context
func (mc *MassifContext) VerifyContext(
	ctx context.Context, options VerifyOptions,
) (*VerifiedContext, error) {
	if options.Check == nil {
		return nil, fmt.Errorf("%w: a checkpoint is required to verify a massif context", ErrSealNotFound)
	}
	check := options.Check

	if check.MMRSize > mc.RangeCount() {
		return nil, fmt.Errorf("%w: MMR size %d < %d", ErrStateSizeExceedsData, mc.RangeCount(), check.MMRSize)
	}

	// Verify the seal signature over the accumulator read from the store: we
	// are checking the store against the sealed state, so any tampering with
	// the sealed peaks is caught here. Of course the seal itself could have
	// been replaced, but at that point the only defense is an independent
	// replica.
	accumulator, err := VerifyCheckpointReceipt(mc, &check.Receipt, options.COSEVerifier)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: failed to verify checkpoint for massif %d", err, mc.Start.MassifIndex)
	}

	// This verifies the sealed accumulator is consistent with any additional
	// committed data in the massif beyond the seal.
	ok, consistentRoots, err := mmr.CheckConsistency(
		mc, sha256.New(), check.MMRSize, mc.RangeCount(), accumulator)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: error verifying accumulator state from massif %d",
			err, mc.Start.MassifIndex)
	}
	if !ok {
		// We don't expect false without error.
		return nil, fmt.Errorf("%w: failed to verify accumulator state massif %d",
			mmr.ErrConsistencyCheck, mc.Start.MassifIndex)
	}

	// If the caller has provided a trusted base state, also verify against
	// that. Typically this is used for 3rd party verification: the 3rd party
	// has saved a previously verified state in a local store, and they want to
	// check the remote log is consistent with the log portion they have
	// locally before replicating the new data.
	if options.TrustedBaseState != nil {
		ok, _, err = mmr.CheckConsistency(
			mc, sha256.New(),
			options.TrustedBaseState.MMRSize,
			mc.RangeCount(),
			options.TrustedBaseState.Peaks)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf(
				"%w: the accumulator produced for the trusted base state doesn't match the root produced for the seal state fetched from the log",
				mmr.ErrConsistencyCheck)
		}
	}

	return &VerifiedContext{
		MassifContext:   *mc,
		Checkpoint:      *check,
		Accumulator:     accumulator,
		ConsistentRoots: consistentRoots,
	}, nil
}
