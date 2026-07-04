package massifs

import (
	"errors"
	"fmt"

	"github.com/forestrie/go-merklelog/mmr"
	"github.com/veraison/go-cose"
)

// ErrVerifierRequired is returned when a checkpoint verification is attempted
// without a COSE verifier. Format-v3 checkpoint receipts carry no key
// material; the verifier must be constructed from a key obtained from a
// trusted store.
var ErrVerifierRequired = errors.New("a COSE verifier is required to verify a checkpoint receipt")

// VerifyCheckpointReceipt verifies a format-v3 checkpoint receipt against the
// log data. The accumulator is read from the massif nodes at the receipt's
// sealed size (proof tree-size-2) and the signature is checked over the COSE
// Sig_structure of its detached payload - the same bytes the univocity
// contract verifies. The receipt's consistency proof is for the
// publisher/on-chain chaining; a local verifier gets the accumulator straight
// from the massif, so any tampering with the massif nodes or the receipt
// fails the signature check.
//
// Returns the verified accumulator (the sealed peaks) on success.
func VerifyCheckpointReceipt(
	store ConsistencyNodeStore, receipt *CheckpointReceipt, verifier cose.Verifier,
) ([][]byte, error) {
	if verifier == nil {
		return nil, ErrVerifierRequired
	}
	size := receipt.Proof.TreeSize2
	if size == 0 {
		return nil, fmt.Errorf("%w: receipt commits to an empty mmr", ErrSealVerifyFailed)
	}
	accumulator, err := mmr.PeakHashes(store, size-1)
	if err != nil {
		return nil, fmt.Errorf("accumulator for sealed size %d: %w", size, err)
	}
	err = verifier.Verify(
		SigStructure(receipt.ProtectedHeader, DetachedPayload(accumulator)),
		receipt.Signature,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: checkpoint receipt for sealed size %d: %v", ErrSealVerifyFailed, size, err)
	}
	return accumulator, nil
}
