package massifs

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/forestrie/go-merklelog/mmr"
	"github.com/veraison/go-cose"
)

// ErrVerifierRequired is returned when a checkpoint verification is attempted
// without a COSE verifier. Format-v3 checkpoint receipts carry no key
// material; the verifier must be constructed from a key obtained from a
// trusted store.
var ErrVerifierRequired = errors.New("a COSE verifier is required to verify a checkpoint receipt")

// nodeWidth is the byte length of every mmr node this package signs and
// verifies (sha256). The detached payload is a raw concatenation, so without
// a fixed width the same signed bytes could be split into entries at other
// boundaries and still verify.
const nodeWidth = sha256.Size

// checkProtectedHeader requires the receipt's protected header to carry a
// COSE algorithm (label 1) that decodes as a CBOR integer, and a tree-size-2
// (ADR-0066) equal to the size the receipt's consistency proof declares and
// to a complete mmr size. The contract's header walk rejects a header
// lacking a readable label 1 with ClaimNotFound(1) or UnexpectedMajorType
// (D9); this must reject the same headers so a header the chain would never
// accept cannot verify off-chain instead — before any signature check, and
// unconditionally, not only when a downstream check happens to consult the
// algorithm. Without the size check, the same signed accumulator is accepted
// at every size with the same peak count: a first checkpoint signed for size
// 1 verifies as size 2^64-1, and a 7 -> 8 extension verifies as 7 -> 10.
// Without the completeness check, mmr.Peaks reads no peaks at all and the
// signature would be checked over an empty payload.
func checkProtectedHeader(receipt *CheckpointReceipt) (size uint64, alg int64, err error) {
	alg, err = ProtectedHeaderAlgorithm(receipt.ProtectedHeader)
	if err != nil {
		return 0, 0, err
	}
	signed, err := ProtectedHeaderTreeSize(receipt.ProtectedHeader)
	if err != nil {
		return 0, 0, err
	}
	size = receipt.Proof.TreeSize2
	if signed != size {
		return 0, 0, fmt.Errorf(
			"%w: signed %d, declared %d", ErrSignedSizeMismatch, signed, size)
	}
	if size == 0 || mmr.MMRSizeForLeafCount(mmr.PeaksBitmap(size)) != size {
		return 0, 0, fmt.Errorf("%w: tree-size-2 %d", mmr.ErrIncompleteTreeSize, size)
	}
	return size, alg, nil
}

// checkNodeWidths requires every path node and right peak of the proof to be
// nodeWidth bytes.
func checkNodeWidths(proof *ConsistencyProof) error {
	for i, path := range proof.Paths {
		for j, node := range path {
			if len(node) != nodeWidth {
				return fmt.Errorf("%w: path %d node %d is %d bytes", ErrNodeWidth, i, j, len(node))
			}
		}
	}
	for i, peak := range proof.RightPeaks {
		if len(peak) != nodeWidth {
			return fmt.Errorf("%w: right peak %d is %d bytes", ErrNodeWidth, i, len(peak))
		}
	}
	return nil
}

// p256HalfOrder is n/2 for P-256; a valid low-s signature has s <= n/2.
var p256HalfOrder = func() *big.Int {
	n, _ := new(big.Int).SetString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
	return new(big.Int).Rsh(n, 1)
}()

// verifyReceiptSignature checks the receipt signature over the COSE
// Sig_structure of the detached payload for accumulator - the same bytes the
// univocity contract verifies. alg is the algorithm read from the protected
// header by checkProtectedHeader, which has already rejected a header whose
// algorithm is absent or not an integer.
func verifyReceiptSignature(receipt *CheckpointReceipt, alg int64, accumulator [][]byte, verifier cose.Verifier) error {
	// The signed algorithm determines the signature scheme (digest, curve and
	// signature encoding), so the verifier must be the one for the algorithm
	// the header commits to. Without this check a header claiming one
	// algorithm could be verified under another's scheme, an acceptance the
	// contract, which dispatches on the same label, refuses. go-cose makes
	// the same check in Sign1Message.Verify; this package builds the
	// Sig_structure itself and so makes it here.
	if alg != int64(verifier.Algorithm()) {
		return fmt.Errorf(
			"%w: checkpoint receipt for sealed size %d: signed algorithm %d, verifier for %d",
			ErrSealVerifyFailed, receipt.Proof.TreeSize2, alg, verifier.Algorithm())
	}
	// The contract's P-256 verifier rejects a high-s signature; go-cose's does
	// not. Reject it here so no checkpoint verifies off-chain that the chain
	// refuses. The sealer normalises to low-s (normalizeSignatureLowS), so no
	// genuine checkpoint is affected.
	if alg == int64(cose.AlgorithmES256) && len(receipt.Signature) == 64 {
		s := new(big.Int).SetBytes(receipt.Signature[32:])
		if s.Cmp(p256HalfOrder) > 0 {
			return fmt.Errorf("%w: checkpoint receipt for sealed size %d: high-s signature",
				ErrSealVerifyFailed, receipt.Proof.TreeSize2)
		}
	}
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
// log data. The signed tree-size-2 must equal the proof's declared size and
// be a complete mmr size; the accumulator is then read from the massif nodes
// at that size and the signature is checked over the COSE Sig_structure of
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
	size, alg, err := checkProtectedHeader(receipt)
	if err != nil {
		return nil, err
	}
	accumulator, err := mmr.PeakHashes(store, size-1)
	if err != nil {
		return nil, fmt.Errorf("accumulator for sealed size %d: %w", size, err)
	}
	if len(accumulator) == 0 {
		return nil, fmt.Errorf("%w: no peaks for sealed size %d", ErrSealVerifyFailed, size)
	}
	if err := verifyReceiptSignature(receipt, alg, accumulator, verifier); err != nil {
		return nil, err
	}
	return accumulator, nil
}

// VerifyCheckpointReceiptFromState verifies a checkpoint receipt without log
// data, from a state the caller already trusts: the accumulator of
// MMR(trustedSize), typically the caller's previously verified checkpoint
// (trustedSize 0 and an empty accumulator for a log the caller has no state
// for). This is the third-party verification path of ADR-0066: the receipt's
// consistency proof is folded from the trusted accumulator with
// mmr.ConsistentRootsForSizes, which fixes the proof shape from the two
// sizes, the right peaks complete the sealed accumulator, and the signature
// is checked over that accumulator.
//
// The origin is the caller's trustedSize, never the receipt's: the declared
// tree-size-1 is unsigned prover context and must equal trustedSize for the
// proof to apply. Returns the verified accumulator of MMR(tree-size-2) on
// success.
func VerifyCheckpointReceiptFromState(
	trustedSize uint64, trustedAccumulator [][]byte,
	receipt *CheckpointReceipt, verifier cose.Verifier,
) ([][]byte, error) {
	if verifier == nil {
		return nil, ErrVerifierRequired
	}
	size, alg, err := checkProtectedHeader(receipt)
	if err != nil {
		return nil, err
	}
	proof := &receipt.Proof
	if proof.TreeSize1 != trustedSize {
		return nil, fmt.Errorf(
			"%w: proof is from size %d, trusted state is size %d",
			ErrConsistencyProofCheck, proof.TreeSize1, trustedSize)
	}
	if err := checkNodeWidths(proof); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConsistencyProofCheck, err)
	}
	roots, expectedRight, err := mmr.ConsistentRootsForSizes(
		sha256.New(), trustedSize, size, trustedAccumulator, proof.Paths)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConsistencyProofCheck, err)
	}
	if len(proof.RightPeaks) != expectedRight {
		return nil, fmt.Errorf(
			"%w: %d right peaks expected for %d -> %d, got %d",
			ErrConsistencyProofCheck, expectedRight, trustedSize, size,
			len(proof.RightPeaks))
	}
	accumulator := make([][]byte, 0, len(roots)+len(proof.RightPeaks))
	accumulator = append(accumulator, roots...)
	accumulator = append(accumulator, proof.RightPeaks...)
	if err := verifyReceiptSignature(receipt, alg, accumulator, verifier); err != nil {
		return nil, err
	}
	return accumulator, nil
}
