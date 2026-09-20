package mmr

import "math/bits"

// LeafCount returns the number of leaves in the largest mmr whose size is <=
// the supplied size. See also [merklelog/mmr/PeakBitmap]
//
// This can safely be use to obtain the leaf index *only* when size is known to
// be a valid mmr size. Typically just before or just after calling AddHashedLeaf
// If in any doubt, instead use LeafIndex() + 1
func LeafCount(size uint64) uint64 {
	return PeaksBitmap(size)
}

func LeafIndex(mmrIndex uint64) uint64 {
	return LeafCount(FirstMMRSize(mmrIndex)) - 1
}

// MMRSizeForLeafCount returns the node count of the complete MMR with `leaves`
// leaves: 2 * leaves - popcount(leaves). Every leaf adds itself plus one
// interior node per binary carry, and each peak is a carry that has not
// happened.
//
// Because PeaksBitmap rounds an incomplete size down to the largest complete
// MMR below it, MMRSizeForLeafCount(PeaksBitmap(size)) == size holds exactly
// for complete sizes. That identity is FirstMMRSize (the draft's complete_mmr)
// in closed form.
func MMRSizeForLeafCount(leaves uint64) uint64 {
	return 2*leaves - uint64(bits.OnesCount64(leaves))
}
