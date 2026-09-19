package massifs

import (
	"crypto/sha256"
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

// checkSignedSizes requires the tree sizes signed in the receipt's protected
// header (ADR-0066 D1) to equal the sizes the receipt's consistency proof
// declares (D5.5). Without this the same signed accumulator is accepted at
// every size with the same peak count: a first checkpoint signed for size 1
// verifies as size 2^64-1, and a 7 -> 8 extension verifies as 7 -> 10. The
// receipt carries a single proof, so the D2 chain endpoints are that proof's
// own sizes.
func checkSignedSizes(receipt *CheckpointReceipt) error {
	signed1, signed2, err := ProtectedHeaderTreeSizes(receipt.ProtectedHeader)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSignedSizeMismatch, err)
	}
	if signed1 != receipt.Proof.TreeSize1 || signed2 != receipt.Proof.TreeSize2 {
		return fmt.Errorf(
			"%w: signed (%d, %d), declared (%d, %d)",
			ErrSignedSizeMismatch, signed1, signed2,
			receipt.Proof.TreeSize1, receipt.Proof.TreeSize2)
	}
	return nil
}

// verifyReceiptSignature checks the receipt signature over the COSE
// Sig_structure of the detached payload for accumulator - the same bytes the
// univocity contract verifies.
func verifyReceiptSignature(receipt *CheckpointReceipt, accumulator [][]byte, verifier cose.Verifier) error {
	err := verifier.Verify(
		SigStructure(receipt.ProtectedHeader, DetachedPayload(accumulator)),
		receipt.Signature,
	)
	if err != nil {
		return fmt.Errorf(
			"%w: checkpoint receipt for sealed size %d: %v",
			ErrSealVerifyFailed, receipt.Proof.TreeSize2, err)
	}
	return nil
}

// VerifyCheckpointReceipt verifies a format-v3 checkpoint receipt against the
// log data. The signed tree sizes must equal the proof's declared sizes; the
// accumulator is then read from the massif nodes at the sealed size (proof
// tree-size-2) and the signature is checked over the COSE Sig_structure of
// its detached payload - the same bytes the univocity contract verifies. The
// receipt's consistency proof is for the publisher/on-chain chaining; a local
// verifier gets the accumulator straight from the massif, so any alteration of
// the massif nodes or the receipt fails the signature check.
//
// Returns the verified accumulator (the sealed peaks) on success.
func VerifyCheckpointReceipt(
	store ConsistencyNodeStore, receipt *CheckpointReceipt, verifier cose.Verifier,
) ([][]byte, error) {
	if verifier == nil {
		return nil, ErrVerifierRequired
	}
	if err := checkSignedSizes(receipt); err != nil {
		return nil, err
	}
	size := receipt.Proof.TreeSize2
	if size == 0 {
		return nil, fmt.Errorf("%w: receipt commits to an empty mmr", ErrSealVerifyFailed)
	}
	accumulator, err := mmr.PeakHashes(store, size-1)
	if err != nil {
		return nil, fmt.Errorf("accumulator for sealed size %d: %w", size, err)
	}
	if err := verifyReceiptSignature(receipt, accumulator, verifier); err != nil {
		return nil, err
	}
	return accumulator, nil
}

// VerifyCheckpointReceiptFromState verifies a checkpoint receipt without log
// data, from a state the caller already trusts: the accumulator of
// MMR(trustedSize), typically the caller's previously verified checkpoint
// (trustedSize 0 and an empty accumulator for a log the caller has no state
// for). This is the third-party verification path of ADR-0066 D8: the
// receipt's consistency proof is folded from the trusted accumulator with
// mmr.ConsistentRootsForSizes, which fixes the proof shape from the two
// sizes, the right peaks complete the sealed accumulator, and the signature
// is checked over that accumulator.
//
// trustedSize is compared with the receipt's declared and signed tree-size-1,
// so the proof cannot select its own origin (D5.4). Returns the verified
// accumulator of MMR(tree-size-2) on success.
func VerifyCheckpointReceiptFromState(
	trustedSize uint64, trustedAccumulator [][]byte,
	receipt *CheckpointReceipt, verifier cose.Verifier,
) ([][]byte, error) {
	if verifier == nil {
		return nil, ErrVerifierRequired
	}
	if err := checkSignedSizes(receipt); err != nil {
		return nil, err
	}
	proof := &receipt.Proof
	if proof.TreeSize1 != trustedSize {
		return nil, fmt.Errorf(
			"%w: declared tree-size-1 %d, trusted size %d",
			ErrSignedSizeMismatch, proof.TreeSize1, trustedSize)
	}
	roots, expectedRight, err := mmr.ConsistentRootsForSizes(
		sha256.New(), trustedSize, proof.TreeSize2, trustedAccumulator, proof.Paths)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConsistencyProofCheck, err)
	}
	if len(proof.RightPeaks) != expectedRight {
		return nil, fmt.Errorf(
			"%w: %d right peaks expected for %d -> %d, got %d",
			ErrConsistencyProofCheck, expectedRight, trustedSize, proof.TreeSize2,
			len(proof.RightPeaks))
	}
	accumulator := make([][]byte, 0, len(roots)+len(proof.RightPeaks))
	accumulator = append(accumulator, roots...)
	accumulator = append(accumulator, proof.RightPeaks...)
	if err := verifyReceiptSignature(receipt, accumulator, verifier); err != nil {
		return nil, err
	}
	return accumulator, nil
}
