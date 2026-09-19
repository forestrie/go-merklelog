package mmr

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
	"math/bits"
)

var (
	ErrConsistencyCheck = errors.New("consistency check failed")
)

// CheckConsistency verifies that the current state mmrSizeB is consistent with
// the provided accumulator for the earlier size A The provided accumulator
// (peakHashesA) should be taken from a trusted source, typically a signed mmr
// state.
//
// See VerifyConsistency for more.
func CheckConsistency(
	store indexStoreGetter, hasher hash.Hash,
	mmrSizeA, mmrSizeB uint64, peakHashesA [][]byte) (bool, [][]byte, error) {

	// Obtain the proofs from the current store
	cp, err := IndexConsistencyProof(store, mmrSizeA-1, mmrSizeB-1)
	if err != nil {
		return false, nil, err
	}

	// Obtain the expected resulting peaks from the current store
	peakHashesB, err := PeakHashes(store, cp.MMRSizeB-1)
	if err != nil {
		return false, nil, err
	}

	return VerifyConsistency(hasher, cp, peakHashesA, peakHashesB)
}

// VerifyConsistency verifies the consistency between two MMR states.
//
// The MMR(A) and MMR(B) states are identified by the fields MMRSizeA and
// MMRSizeB in the proof. peakHashesA and B are the node values corresponding to
// the MMR peaks of each respective state. The Path in the proof contains the
// nodes necessary to prove each A-peak reaches a B-peak. The path contains the
// inclusion proofs for each A-peak in MMR(B).
//
//	    MMR(A):[7, 8]      MMR(B):[7, 10, 11]
//	 2       7                7
//	       /   \            /   \
//	 1    3     6          3     6    10
//	     / \  /  \        / \  /  \   / \
//	 0  1   2 4   5 8    1   2 4   5 8   9 11
//
//		Path MMR(A) -> MMR(B)
//		7 in MMR(B) -> []
//		8 in MMR(B) -> [9]
//		Path = [[], [9]]
func VerifyConsistency(
	hasher hash.Hash,
	cp ConsistencyProof, peaksFrom [][]byte, peaksTo [][]byte) (bool, [][]byte, error) {

	// Equal sizes describe one state: nothing is proven and nothing is new.
	// The proof shape the sizes imply is one empty path per peak, and the
	// target accumulator must equal the origin accumulator. Callers such as
	// GetContextVerified reach this when a massif has not grown past its seal.
	if cp.MMRSizeA == cp.MMRSizeB {
		return verifySameState(cp, peaksFrom, peaksTo)
	}

	// Get the peaks proven by the consistency proof using the provided peaks
	// for mmr size A. ConsistentRootsForSizes additionally requires the proof
	// to have exactly the shape the two sizes imply, and requires size B to be
	// a complete mmr size.
	proven, expectedRight, err := ConsistentRootsForSizes(
		hasher, cp.MMRSizeA, cp.MMRSizeB, peaksFrom, cp.Path)
	if err != nil {
		return false, nil, err
	}

	// The accumulator for MMR(sizeB) consists of the proven peaks followed by
	// the right peaks, which no proof reaches. Requiring the count to match
	// means peaksTo has no surplus or missing entries.
	if len(peaksTo) != len(proven)+expectedRight {
		return false, nil, fmt.Errorf(
			"%w: %d target peaks expected, got %d",
			ErrConsistencyCheck, len(proven)+expectedRight, len(peaksTo))
	}

	// The proven peaks are the peaks of MMR(sizeB) in descending height order,
	// so they must be a prefix of peaksTo.
	for i, root := range proven {
		if !bytes.Equal(peaksTo[i], root) {
			return false, nil, fmt.Errorf(
				"%w: target peak %d does not match the proven root",
				ErrConsistencyCheck, i)
		}
	}

	return true, peaksTo, nil
}

// verifySameState is the MMRSizeA == MMRSizeB case of VerifyConsistency: the
// accumulator of the one state must be supplied for both sides, with one empty
// path per peak.
func verifySameState(cp ConsistencyProof, peaksFrom, peaksTo [][]byte) (bool, [][]byte, error) {
	n := bits.OnesCount64(PeaksBitmap(cp.MMRSizeA))
	if len(peaksFrom) != n || len(cp.Path) != n {
		return false, nil, fmt.Errorf(
			"%w: %d peaks for size %d, got %d accumulator entries and %d paths",
			ErrConsistencyPeakCount, n, cp.MMRSizeA, len(peaksFrom), len(cp.Path))
	}
	for i, path := range cp.Path {
		if len(path) != 0 {
			return false, nil, fmt.Errorf(
				"%w: path %d: expected length 0, got %d",
				ErrConsistencyPathLength, i, len(path))
		}
	}
	if len(peaksTo) != n {
		return false, nil, fmt.Errorf(
			"%w: %d target peaks expected, got %d", ErrConsistencyCheck, n, len(peaksTo))
	}
	for i := range peaksFrom {
		if !bytes.Equal(peaksTo[i], peaksFrom[i]) {
			return false, nil, fmt.Errorf(
				"%w: target peak %d does not match the origin peak", ErrConsistencyCheck, i)
		}
	}
	return true, peaksTo, nil
}
