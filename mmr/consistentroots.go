package mmr

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
	"math/bits"
)

var (
	ErrAccumulatorProofLen = errors.New("a proof for each accumulator is required")

	// The sentinel errors below mirror the conditions checked by
	// ConsistentRootsForSizes. Each is wrapped with the values that failed the
	// check.

	// ErrSizesNotIncreasing is returned when the target size does not exceed
	// the origin size, in which case there is no growth to prove.
	ErrSizesNotIncreasing = errors.New("the target size must exceed the origin size")
	// ErrIncompleteTreeSize is returned when the size is not the node count of
	// any complete MMR.
	ErrIncompleteTreeSize = errors.New("the size is not a complete mmr size")
	// ErrConsistencyPeakCount is returned when the accumulator entry count or
	// the proof count differs from the peak count the origin size implies.
	ErrConsistencyPeakCount = errors.New("the accumulator or proof count does not match the origin peak count")
	// ErrConsistencyPathLength is returned when a path length differs from the
	// length the two sizes imply for that peak.
	ErrConsistencyPathLength = errors.New("the path length does not match the length the sizes imply")
	// ErrConsistencyRootMismatch is returned when two paths that the sizes
	// place under one target peak prove different roots.
	ErrConsistencyRootMismatch = errors.New("paths under a single target peak prove different roots")
)

// ConsistentRoots  is supplied with the accumulator from which consistency is
// being shown, and an inclusion proof for each accumulator entry in a future MMR
// state.
//
// The algorithm recovers the necessary prefix (peaks) of the future
// accumulator against which the proofs were obtained.
// It is typical that many nodes in the original accumulator share the same peak in the new accumulator.
// The returned list will be a descending height ordered list of elements from the
// accumulator for the consistent future state. It may be exactly the future
// accumulator or it may be a prefix of it.
//
// The order of the roots returned matches the order of the nodes in the accumulator.
//
// Args:
//   - ifrom the last node index of the the complete MMR from which consistency was proven.
//   - accumulatorfrom the node values correponding to the peaks of the accumulator at MMR(sizeA)
//   - proofs the inclusion proofs for each node in accumulatorfrom in MMR(sizeB)
func ConsistentRoots(hasher hash.Hash, ifrom uint64, accumulatorfrom [][]byte, proofs [][][]byte) ([][]byte, error) {
	frompeaks := Peaks(ifrom)

	if len(frompeaks) != len(proofs) {
		return nil, ErrAccumulatorProofLen
	}

	roots := [][]byte{}

	for i := range accumulatorfrom {
		// remembering that peaks are 1 based (for now)
		root := IncludedRoot(hasher, frompeaks[i], accumulatorfrom[i], proofs[i])
		// The nature of MMR's is that many nodes are committed by the
		// same accumulator peak, and that peak changes with
		// low frequency.
		if len(roots) > 0 && bytes.Equal(roots[len(roots)-1], root) {
			continue
		}
		roots = append(roots, root)
	}

	return roots, nil
}

// ConsistentRootsForSizes produces the peaks of MMR(sizeTo) that the proofs
// prove from the peaks of MMR(sizeFrom), requiring the proofs to have exactly
// the shape the two sizes imply (the draft's SHOULD on path lengths, checked in
// the same pass as the hashing).
//
// Sizes are node counts: MMR(i) has i + 1 nodes. sizeFrom MUST be the size of
// the state the verifier already trusts; if it is taken from the proof the
// check is void. Only sizeTo is required to be a complete MMR size: every
// trusted size was itself a checked target.
//
// For a complete MMR the set bits of PeaksBitmap(size) are the peak heights,
// high to low, which is accumulator order. Let split be the highest bit on
// which the two bitmaps differ; as sizeTo > sizeFrom the target has it and the
// origin does not. An origin peak above split is also a peak of the target: its
// path is empty and it is returned unchanged. Every origin peak below split is
// committed by the target peak of height split: its path has length split - h,
// and every such path must prove the same root. The target's remaining peaks
// lie below every origin peak, so no proof reaches them; the prover supplies
// them as right peaks, and their count is returned.
//
// Args:
//   - sizeFrom node count of the origin state (0 for an empty log)
//   - sizeTo node count of the target state
//   - accumulatorFrom the peaks of MMR(sizeFrom), descending height
//   - proofs one path per origin peak, in the same order
//
// Returns:
//   - roots the peaks of MMR(sizeTo) proven from the origin peaks, in
//     descending height: the unchanged peaks, then the one proven root if any
//   - expectedRight the number of MMR(sizeTo) peaks the prover must supply as
//     right peaks. roots plus those peaks is the accumulator of MMR(sizeTo).
func ConsistentRootsForSizes(
	hasher hash.Hash, sizeFrom, sizeTo uint64,
	accumulatorFrom [][]byte, proofs [][][]byte,
) ([][]byte, int, error) {

	if sizeTo <= sizeFrom {
		return nil, 0, fmt.Errorf(
			"%w: from=%d, to=%d", ErrSizesNotIncreasing, sizeFrom, sizeTo)
	}

	to := PeaksBitmap(sizeTo)
	// PeaksBitmap rounds an incomplete size down to the largest MMR below it,
	// so `to` describes MMR(sizeTo) only if sizeTo is complete. Without this a
	// target such as 6 anchors an accumulator that is no MMR's, and a verifier
	// later reads its entries at the wrong heights.
	if MMRSizeForLeafCount(to) != sizeTo {
		return nil, 0, fmt.Errorf("%w: to=%d", ErrIncompleteTreeSize, sizeTo)
	}
	from := PeaksBitmap(sizeFrom)
	n := bits.OnesCount64(from)
	if len(accumulatorFrom) != n {
		return nil, 0, fmt.Errorf(
			"%w: %d accumulator entries for size %d, got %d",
			ErrConsistencyPeakCount, n, sizeFrom, len(accumulatorFrom))
	}
	if len(proofs) != n {
		return nil, 0, fmt.Errorf(
			"%w: %d proofs for size %d, got %d",
			ErrConsistencyPeakCount, n, sizeFrom, len(proofs))
	}
	nto := bits.OnesCount64(to)
	if n == 0 {
		// Nothing is proven from an empty origin, so every target peak is a
		// right peak.
		return [][]byte{}, nto, nil
	}

	split := BitLength(from^to) - 1
	roots := make([][]byte, 0, n)
	// Nodes preceding the current origin peak's subtree; a peak of height h
	// sits at offset + 2^(h+1) - 2 and its subtree has 2^(h+1) - 1 nodes.
	offset := uint64(0)
	i := 0

	// Origin peaks above the split are also peaks of the target. The path is
	// not read; requiring it to be empty rejects surplus material (a shape
	// check: the result does not depend on it).
	for h := BitLength(from) - 1; h > split; h-- {
		if (from>>uint(h))&1 == 0 {
			continue
		}
		if len(proofs[i]) != 0 {
			return nil, 0, fmt.Errorf(
				"%w: path %d: expected length 0, got %d",
				ErrConsistencyPathLength, i, len(proofs[i]))
		}
		roots = append(roots, accumulatorFrom[i])
		offset += (uint64(1) << uint(h+1)) - 1
		i++
	}

	// Origin peaks below the split are all committed by the target peak of
	// height split (bit split itself is clear in from), so each path must have
	// length split - h and every path must prove the same root. The first
	// `above` peaks were returned unchanged, so i == above at the first peak
	// below the split.
	above := len(roots)
	var root []byte
	for h := split - 1; h >= 0; h-- {
		if (from>>uint(h))&1 == 0 {
			continue
		}
		expected := split - h
		if len(proofs[i]) != expected {
			return nil, 0, fmt.Errorf(
				"%w: path %d: expected length %d, got %d",
				ErrConsistencyPathLength, i, expected, len(proofs[i]))
		}
		subtree := (uint64(1) << uint(h+1)) - 1
		proven := IncludedRoot(
			hasher, offset+subtree-1, accumulatorFrom[i], proofs[i])
		if i == above {
			root = proven
		} else if !bytes.Equal(proven, root) {
			return nil, 0, fmt.Errorf(
				"%w: path %d proves a different root from the paths before it",
				ErrConsistencyRootMismatch, i)
		}
		offset += subtree
		i++
	}
	if n > above {
		roots = append(roots, root)
	}

	return roots, nto - len(roots), nil
}
