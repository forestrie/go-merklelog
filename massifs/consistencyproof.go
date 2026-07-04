package massifs

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/forestrie/go-merklelog/mmr"
)

// ConsistencyNodeStore reads mmr node values by index. A MassifContext
// satisfies this.
type ConsistencyNodeStore interface {
	Get(i uint64) ([]byte, error)
}

// BuildConsistencyProof builds the format-v3 consistency proof carrying the
// accumulator of MMR(fromSize) to the accumulator of MMR(toSize), per the
// draft consistent_roots algorithm the univocity contract implements.
// fromSize == 0 means the log has no on-chain state yet: no paths, the full
// target accumulator as right-peaks. Both sizes must be complete mmr sizes;
// toSize is typically a sealed checkpoint's mmr size.
func BuildConsistencyProof(store ConsistencyNodeStore, fromSize, toSize uint64) (ConsistencyProof, error) {
	if toSize <= fromSize {
		return ConsistencyProof{}, fmt.Errorf("toSize %d must be greater than fromSize %d", toSize, fromSize)
	}
	peaksTo, err := mmr.PeakHashes(store, toSize-1)
	if err != nil {
		return ConsistencyProof{}, fmt.Errorf("peaks of target size %d: %w", toSize, err)
	}

	proof := ConsistencyProof{
		TreeSize1: fromSize,
		TreeSize2: toSize,
		Paths:     [][][]byte{},
	}

	if fromSize == 0 {
		proof.RightPeaks = peaksTo
		return proof, nil
	}

	cp, err := mmr.IndexConsistencyProof(store, fromSize-1, toSize-1)
	if err != nil {
		return ConsistencyProof{}, fmt.Errorf("consistency proof %d -> %d: %w", fromSize, toSize, err)
	}
	peaksFrom, err := mmr.PeakHashes(store, fromSize-1)
	if err != nil {
		return ConsistencyProof{}, fmt.Errorf("peaks of origin size %d: %w", fromSize, err)
	}

	// The proven roots are a prefix of the target accumulator; whatever the
	// paths do not reach is carried explicitly as right-peaks.
	roots, err := mmr.ConsistentRoots(sha256.New(), fromSize-1, peaksFrom, cp.Path)
	if err != nil {
		return ConsistencyProof{}, fmt.Errorf("consistent roots %d -> %d: %w", fromSize, toSize, err)
	}
	for i := range roots {
		if !bytes.Equal(roots[i], peaksTo[i]) {
			return ConsistencyProof{}, fmt.Errorf("proven root %d does not match target accumulator", i)
		}
	}

	proof.Paths = cp.Path
	proof.RightPeaks = peaksTo[len(roots):]
	return proof, nil
}
