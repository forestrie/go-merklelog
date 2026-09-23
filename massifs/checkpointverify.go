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
// (ADR-0066) equal to the size the receipt's last consistency proof declares
// and to a complete mmr size. The contract's header walk rejects a header
// lacking a readable label 1 with ClaimNotFound(1) or UnexpectedMajorType
// (D9); this must reject the same headers so a header the chain would never
// accept cannot verify off-chain instead — before any signature check, and
// unconditionally, not only when a downstream check happens to consult the
// algorithm. Without the size check, the same signed accumulator is accepted
// at every size with the same peak count: a first checkpoint signed for size
// 1 verifies as size 2^64-1, and a 7 -> 8 extension verifies as 7 -> 10.
// Without the completeness check, mmr.Peaks reads no peaks at all and the
// signature would be checked over an empty payload. On a relayed chain the
// size compared is the last proof's: an intermediate step is reached from
// trusted state by the fold, and a receipt whose signed size named an
// intermediate step would leave the final accumulator unsigned (ADR-0066 D2).
func checkProtectedHeader(receipt *CheckpointReceipt) (size uint64, alg int64, err error) {
	if len(receipt.Proofs) == 0 {
		return 0, 0, ErrProofChainEmpty
	}
	alg, err = ProtectedHeaderAlgorithm(receipt.ProtectedHeader)
	if err != nil {
		return 0, 0, err
	}
	signed, err := ProtectedHeaderTreeSize(receipt.ProtectedHeader)
	if err != nil {
		return 0, 0, err
	}
	size = receipt.Proofs[len(receipt.Proofs)-1].TreeSize2
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

// checkProofChain requires the chain to start at the size the verifier
// already trusts, to be contiguous - each proof picks up where its
// predecessor left off - and for each proof's tree-size-2 to exceed its
// tree-size-1 (GML15-F2). A gap or an overlap would let a relay present
// proofs of two unrelated extensions as one, and the intermediate sizes are
// unsigned (ADR-0066 D2), so this comparison is the only thing that links
// them. A zero-length or backwards link proves nothing and is not a
// consistency proof: the univocity contract rejects it
// (treeSize2 <= treeSize1, src/checkpoints/lib/consistencyReceipt.sol) and
// the draft requires tree-size-2 to exceed tree-size-1, so a store-backed
// verify - which only checks contiguity, having no folded state of its own to
// reject a degenerate link the way mmr.ConsistentRootsForSizes does on the
// from-state path - must reject the same chains the chain would.
func checkProofChain(proofs []ConsistencyProof, trustedSize uint64) error {
	if len(proofs) == 0 {
		return ErrProofChainEmpty
	}
	from := trustedSize
	for i, proof := range proofs {
		if proof.TreeSize1 != from {
			if i == 0 {
				return fmt.Errorf(
					"%w: proof is from size %d, trusted state is size %d",
					ErrConsistencyProofCheck, proof.TreeSize1, from)
			}
			return fmt.Errorf(
				"%w: proof %d is from size %d, proof %d ends at size %d",
				ErrProofChainNotContiguous, i, proof.TreeSize1, i-1, from)
		}
		if proof.TreeSize2 <= proof.TreeSize1 {
			return fmt.Errorf("%w: proof %d: %w: from=%d, to=%d",
				ErrConsistencyProofCheck, i, mmr.ErrSizesNotIncreasing,
				proof.TreeSize1, proof.TreeSize2)
		}
		from = proof.TreeSize2
	}
	return nil
}

// verifyReceiptSignature checks the receipt signature over the COSE
// Sig_structure of the detached payload for accumulator - the same bytes the
// univocity contract verifies.
// p256HalfOrder is n/2 for P-256; a valid low-s signature has s <= n/2.
var p256HalfOrder = func() *big.Int {
	n, _ := new(big.Int).SetString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
	return new(big.Int).Rsh(n, 1)
}()

func verifyReceiptSignature(
	receipt *CheckpointReceipt, alg int64, size uint64, accumulator [][]byte,
	verifier cose.Verifier,
) error {
	// The contract's P-256 verifier rejects a high-s signature; go-cose's does
	// not. Reject it here so no checkpoint verifies off-chain that the chain
	// refuses. The sealer normalises to low-s (normalizeSignatureLowS), so no
	// genuine checkpoint is affected. alg is already known to be a CBOR
	// integer (checkProtectedHeader ran first), so unlike before this guard
	// is never silently skipped for a header whose algorithm could not be
	// read.
	if alg == int64(cose.AlgorithmES256) && len(receipt.Signature) == 64 {
		s := new(big.Int).SetBytes(receipt.Signature[32:])
		if s.Cmp(p256HalfOrder) > 0 {
			return fmt.Errorf("%w: checkpoint receipt for sealed size %d: high-s signature",
				ErrSealVerifyFailed, size)
		}
	}
	err := verifier.Verify(
		SigStructure(receipt.ProtectedHeader, DetachedPayload(accumulator)),
		receipt.Signature,
	)
	if err != nil {
		return fmt.Errorf(
			"%w: checkpoint receipt for sealed size %d: %v",
			ErrSealVerifyFailed, size, err)
	}
	return nil
}

// VerifyCheckpointReceipt verifies a format-v3 checkpoint receipt against the
// log data. The signed tree-size-2 must equal the last proof's declared size
// and be a complete mmr size, and a relayed chain must be contiguous; the
// accumulator is then read from the massif nodes at the signed size and the
// signature is checked over the COSE Sig_structure of its detached payload -
// the same bytes the univocity contract verifies. The receipt's consistency
// proofs are for the publisher/on-chain chaining; a local verifier gets the
// accumulator straight from the massif, so any alteration of the massif nodes
// or the receipt fails the signature check. The chain is not folded here:
// there is no trusted origin to fold from that the massif does not already
// supply, and folding from a size the receipt itself declares would prove
// nothing (ADR-0066 D5.4). VerifyCheckpointReceiptFromState is the folding
// path.
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
	// The first proof's declared origin is the only base available here, so
	// contiguity is all that can be checked; it still rejects a chain whose
	// links do not join.
	if err := checkProofChain(receipt.Proofs, receipt.Proofs[0].TreeSize1); err != nil {
		return nil, err
	}
	accumulator, err := mmr.PeakHashes(store, size-1)
	if err != nil {
		return nil, fmt.Errorf("accumulator for sealed size %d: %w", size, err)
	}
	if len(accumulator) == 0 {
		return nil, fmt.Errorf("%w: no peaks for sealed size %d", ErrSealVerifyFailed, size)
	}
	if err := verifyReceiptSignature(receipt, alg, size, accumulator, verifier); err != nil {
		return nil, err
	}
	return accumulator, nil
}

// VerifyCheckpointReceiptFromState verifies a checkpoint receipt without log
// data, from a state the caller already trusts: the accumulator of
// MMR(trustedSize), typically the caller's previously verified checkpoint
// (trustedSize 0 and an empty accumulator for a log the caller has no state
// for). This is the third-party verification path of ADR-0066: each of the
// receipt's consistency proofs is folded in turn from the trusted
// accumulator with mmr.ConsistentRootsForSizes, which fixes the proof shape
// from the two sizes, the right peaks complete each step's accumulator, and
// the signature is checked over the accumulator the last step reaches.
//
// The origin is the caller's trustedSize, never the receipt's: a declared
// tree-size-1 is unsigned prover context. The first proof's must equal
// trustedSize and each later one's must equal the size its predecessor
// reached, so every step of a relayed chain is pinned to state the caller
// already trusts (ADR-0066 D2, D5.4). Returns the verified accumulator of
// MMR(tree-size-2) on success.
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
	if err := checkProofChain(receipt.Proofs, trustedSize); err != nil {
		return nil, err
	}
	accumulator := trustedAccumulator
	sizeFrom := trustedSize
	for i := range receipt.Proofs {
		proof := &receipt.Proofs[i]
		if err := checkNodeWidths(proof); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrConsistencyProofCheck, err)
		}
		roots, expectedRight, err := mmr.ConsistentRootsForSizes(
			sha256.New(), sizeFrom, proof.TreeSize2, accumulator, proof.Paths)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrConsistencyProofCheck, err)
		}
		if len(proof.RightPeaks) != expectedRight {
			return nil, fmt.Errorf(
				"%w: %d right peaks expected for %d -> %d, got %d",
				ErrConsistencyProofCheck, expectedRight, sizeFrom, proof.TreeSize2,
				len(proof.RightPeaks))
		}
		next := make([][]byte, 0, len(roots)+len(proof.RightPeaks))
		next = append(next, roots...)
		next = append(next, proof.RightPeaks...)
		accumulator = next
		sizeFrom = proof.TreeSize2
	}
	// checkProtectedHeader already required the signed size to be the last
	// proof's, which the fold has now reached.
	if sizeFrom != size {
		return nil, fmt.Errorf(
			"%w: the chain ends at size %d, the signed size is %d",
			ErrProofChainNotContiguous, sizeFrom, size)
	}
	if err := verifyReceiptSignature(receipt, alg, size, accumulator, verifier); err != nil {
		return nil, err
	}
	return accumulator, nil
}
