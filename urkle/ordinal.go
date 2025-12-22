package urkle

import "errors"

var (
	// ErrLeafOrdinalNotPresent indicates the leafOrdinal is within capacity but not yet filled.
	ErrLeafOrdinalNotPresent = errors.New("urkle: leaf ordinal not present")
)

// LeafOrdinalKey16 returns the idtimestamp for leafOrdinal if it is present, otherwise 0.
//
// Presence is decided by nextLeaf (the number of filled leaves in the chunk).
//
// NOTE: This only makes sense if nextLeaf is authenticated by higher-level chunk metadata.
func LeafOrdinalKey16(v IndexView, leafOrdinal uint16, nextLeaf uint32) uint64 {
	ord := uint32(leafOrdinal)
	if ord >= nextLeaf {
		return 0
	}

	// Capacity guard (defensive; nextLeaf should already be <= LeafCount).
	if uint64(ord) >= v.LeafCount {
		return 0
	}

	return LeafKey(v.LeafTable, ord)
}

// LeafOrdinalInclusionProof returns an inclusion proof for the leaf at leafOrdinal.
//
// It returns the proof and the recovered key (idtimestamp).
func LeafOrdinalInclusionProof(v IndexView, leafOrdinal uint16, nextLeaf uint32, root Ref) (InclusionProof, uint64, error) {
	ord := uint32(leafOrdinal)
	if ord >= nextLeaf {
		return InclusionProof{}, 0, ErrLeafOrdinalNotPresent
	}
	if uint64(ord) >= v.LeafCount {
		return InclusionProof{}, 0, ErrInvalidLeafOrdinal
	}

	key := LeafKey(v.LeafTable, ord)
	p, err := ProveInclusion(v.LeafTable, v.NodeStore, root, key)
	if err != nil {
		return InclusionProof{}, key, err
	}
	return p, key, nil
}
