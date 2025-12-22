package urkle

// NodeRecordOffset returns the byte offset of ref in nodeStore.
func NodeRecordOffset(ref Ref) uint64 {
	return uint64(ref) * NodeRecordBytes
}

func nodeRec(nodeStore []byte, ref Ref) []byte {
	off := NodeRecordOffset(ref)
	return nodeStore[off : off+NodeRecordBytes]
}

// NodeKindAt returns the kind field for a node record.
func NodeKindAt(nodeStore []byte, ref Ref) NodeKind {
	return NodeKind(nodeRec(nodeStore, ref)[0])
}

// NodeBit returns the branch crit-bit index (only meaningful for KindBranch).
func NodeBit(nodeStore []byte, ref Ref) uint8 {
	return nodeRec(nodeStore, ref)[1]
}

// NodeRightSpan returns the node-count of the right subtree (only meaningful for KindBranch).
func NodeRightSpan(nodeStore []byte, ref Ref) uint32 {
	return readU32BE(nodeRec(nodeStore, ref)[4:8])
}

// NodeSubtreeSize returns the node-count of this subtree (incl this node).
func NodeSubtreeSize(nodeStore []byte, ref Ref) uint32 {
	return readU32BE(nodeRec(nodeStore, ref)[8:12])
}

// NodeLeafOrdinal returns leafOrdinal (only meaningful for KindLeaf).
func NodeLeafOrdinal(nodeStore []byte, ref Ref) uint32 {
	return readU32BE(nodeRec(nodeStore, ref)[12:16])
}

// NodeHash returns the stored node hash.
func NodeHash(nodeStore []byte, ref Ref) [HashBytes]byte {
	var out [HashBytes]byte
	copy(out[:], nodeRec(nodeStore, ref)[32:32+HashBytes])
	return out
}

func nodeWriteHash(rec []byte, h [HashBytes]byte) {
	copy(rec[32:32+HashBytes], h[:])
}

// NodeWriteLeaf writes a leaf record in-place.
func NodeWriteLeaf(nodeStore []byte, ref Ref, leafOrdinal uint32, h [HashBytes]byte) {
	rec := nodeRec(nodeStore, ref)
	rec[0] = byte(KindLeaf)
	rec[1] = 0
	writeU32BE(rec[4:8], 0)  // rightSpan
	writeU32BE(rec[8:12], 1) // subtreeSize
	writeU32BE(rec[12:16], leafOrdinal)
	nodeWriteHash(rec, h)
}

// NodeWriteBranch writes a branch record in-place.
func NodeWriteBranch(nodeStore []byte, ref Ref, bit uint8, rightSpan uint32, subtreeSize uint32, h [HashBytes]byte) {
	rec := nodeRec(nodeStore, ref)
	rec[0] = byte(KindBranch)
	rec[1] = bit
	writeU32BE(rec[4:8], rightSpan)
	writeU32BE(rec[8:12], subtreeSize)
	writeU32BE(rec[12:16], 0)
	nodeWriteHash(rec, h)
}
