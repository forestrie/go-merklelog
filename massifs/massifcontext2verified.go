package massifs

import (
	"context"
	"crypto/sha256"
	"fmt"

	commoncbor "github.com/datatrails/go-datatrails-common/cbor"
	commoncose "github.com/datatrails/go-datatrails-common/cose"
	"github.com/datatrails/go-datatrails-merklelog/mmr"
	"github.com/veraison/go-cose"
)

type checkpointGetter interface {
	GetCheckpoint(ctx context.Context, massifIndex uint32) (*Checkpoint, error)
}

type VerifyOptions struct {
	Check            *Checkpoint
	TrustedBaseState *MMRState
	COSECodec        commoncbor.CBORCodec
	COSEVerifier     cose.Verifier
}

type VerifiedContext2 struct {
	MassifContext2

	// The signed message that was used to verify the massif data. Verification
	// will use the public key from this message. The verification method allows
	// the caller to provide the public key they expect, based on having
	// obtained it from a store they trust. Where the expected public key has
	// been provided it is required to match the key found on the seal from the
	// store (which may be local or remote).
	Sign1Message commoncose.CoseSign1Message
	// MMRState describes the sealed (confirmed) range of the massif. For a verified massif
	// context it is guaranteed to refer to the portion of the log identified by
	// massifIndex, but the committed data may extend past the data confirmed by
	// the seal.
	MMRState MMRState

	// ConsistentRoots is the result of verifying the entire range of the massif
	// context data against the seal state for the massif. If a previously
	// trusted state was provided when verification was performed, this state is
	// also consistent with that.  When configured to use "bagged" peaks for
	// verification purposes, this will be the single bagged root of the mmr up to the
	// end of the data.  Otherwise, it will be the accumulator peaks.
	ConsistentRoots [][]byte
}

// GetSignedRoot retrieves the signed root for a massif identified by its index.
// verifyContext verifies the log data in the context is consistent with its seal
// optionally also checks consistency against a provided state from a trusted source
// Returns:
//   - a VerifiedContext which references the dynamically allocated aspects of this context
func (mc *MassifContext2) verifyContext(
	ctx context.Context, options VerifyOptions,
) (*VerifiedContext2, error) {

	state := options.Check.MMRState

	if state.MMRSize > mc.RangeCount() {
		return nil, fmt.Errorf("%w: MMR size %d < %d", ErrStateSizeExceedsData, mc.RangeCount(), state.MMRSize)
	}

	switch state.Version {
	case int(MMRStateVersion1):
		fallthrough
	case int(MMRStateVersion2):
		return mc.verifyContextV1V2(&options.Check.Sign1Message, state, options)

	// we don't support v0 anymore
	default:
		return nil, fmt.Errorf("unsupported MMR state version %d", state.Version)
	}
}

func (mc *MassifContext2) verifyContextV1V2(
	msg *commoncose.CoseSign1Message, state MMRState, options VerifyOptions,
) (*VerifiedContext2, error) {
	var ok bool
	var err error
	var peaksB [][]byte

	// There is no difference between v1 and v2 for the purposes of verification.
	// We just need to accept both here.
	if state.Version != int(MMRStateVersion1) && state.Version != int(MMRStateVersion2) {
		return nil, fmt.Errorf("unsupported MMR state version %d", state.Version)
	}

	// get the peaks from the local store, we are checking the store against the
	// latest additions. as we verify the signature below, any changes to the
	// store will be caught.
	state.Peaks, err = mmr.PeakHashes(mc, state.MMRSize-1)
	if err != nil {
		return nil, err
	}

	// Ensure the peaks we read from the store are the ones that were signed.
	// Otherwise we can get caught out by the store tampered after the seal was
	// created. Of course the seal itself could have been replaced, but at that
	// point the only defense is an indpendent replica.

	msg.Payload, err = options.COSECodec.MarshalCBOR(state)
	if err != nil {
		return nil, err
	}

	err = msg.Verify(nil, options.COSEVerifier)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: failed to verify checkpoint for massif %d: %v",
			ErrSealVerifyFailed, mc.Start.MassifIndex, err)
	}

	// This verifies the peaks read from mmrSizeA are consistent with mmrSizeB.
	ok, peaksB, err = mmr.CheckConsistency(
		mc, sha256.New(), state.MMRSize, mc.RangeCount(), state.Peaks)
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
	// that. Typically this is used for 3d party verification, the 3rd party has
	// saved a previously verified state in a local store, and they want to
	// check the remote log is consistent with the log portion they have locally
	// before replicating the new data.
	if options.TrustedBaseState != nil {

		if options.TrustedBaseState.Version == int(MMRStateVersion0) {
			return nil, fmt.Errorf("unsupported MMR state version 0 (you should promote to v1 on demand using mmr.PeakHashes)")
		}

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

	return &VerifiedContext2{
		MassifContext2:   *mc,
		Sign1Message:    *msg,
		MMRState:        state,
		ConsistentRoots: peaksB,
	}, nil
}
