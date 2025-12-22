package urkle

import "math/bits"

// NodeCountMax returns the maximum number of nodes in a binary trie with leafCount distinct keys.
// For a Patricia/crit-bit style binary trie, node count is <= 2N-1.
func NodeCountMax(leafCount uint64) uint64 {
	if leafCount == 0 {
		return 0
	}
	return 2*leafCount - 1
}

// LeafTableBytes returns the required leaf table bytes for leafCount leaves.
func LeafTableBytes(leafCount uint64) uint64 {
	return leafCount * LeafRecordBytes
}

// NodeStoreBytes returns the required node store bytes for leafCount leaves,
// allocating up to the maximum possible node count (2N-1).
func NodeStoreBytes(leafCount uint64) uint64 {
	return NodeCountMax(leafCount) * NodeRecordBytes
}

// CheckLeafCount checks whether leafCount can be represented in the on-disk structures.
func CheckLeafCount(leafCount uint64) error {
	if leafCount > uint64(^uint32(0)) {
		return ErrLeafCountDoesNotFit32
	}
	return nil
}

// LeafOrdinalBits returns ceil(log2(leafCount)), i.e. the number of bits required
// to represent leafOrdinal values in [0..leafCount-1].
//
// NOTE: leafCount must be > 0.
func LeafOrdinalBits(leafCount uint64) uint8 {
	if leafCount <= 1 {
		return 0
	}
	// For N>0, bits = ceil(log2(N)) = floor(log2(N-1)) + 1
	return uint8(bits.Len64(leafCount - 1))
}
