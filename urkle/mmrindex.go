package urkle

import "github.com/forestrie/go-merklelog/mmr"

// LeafOrdinalToMMRIndex derives the MMR leaf node index for a chunk-local leafOrdinal.
//
// firstLeafMMRIndex is the MMR index of the first leaf in the chunk (from massif start context).
//
// The result is the MMR index of the leaf corresponding to leafOrdinal within the overall log MMR.
func LeafOrdinalToMMRIndex(firstLeafMMRIndex uint64, leafOrdinal uint64) uint64 {
	firstLeafIndex := mmr.LeafIndex(firstLeafMMRIndex)
	return mmr.MMRIndex(firstLeafIndex + leafOrdinal)
}
