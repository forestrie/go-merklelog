package urkle

const (
	leafKeyBytes    = 8
	leafValueBytes  = HashBytes
	leafExtra1Bytes = HashBytes - 8
	leafExtraBytes  = HashBytes

	leafValueOff = leafKeyBytes
	leafExtraOff = leafValueOff + leafValueBytes

	leafExtra1Off = leafExtraOff
	leafExtra2Off = leafExtra1Off + leafExtra1Bytes
	leafExtra3Off = leafExtra2Off + leafExtraBytes

	leafExtraFields = 3
)

// LeafRecordOffset returns the byte offset of leafOrdinal in leafTable.
func LeafRecordOffset(leafOrdinal uint32) uint64 {
	return uint64(leafOrdinal) * LeafRecordBytes
}

// LeafSet stores (key,valueBytes) for leafOrdinal in leafTable.
// Caller must ensure leafTable is large enough.
func LeafSet(leafTable []byte, leafOrdinal uint32, key uint64, valueBytes []byte) {
	if len(valueBytes) != HashBytes {
		panic("urkle: bad valueBytes length")
	}
	off := LeafRecordOffset(leafOrdinal)
	writeU64BE(leafTable[off:off+8], key)
	copy(leafTable[off+leafValueOff:off+leafValueOff+HashBytes], valueBytes)

	// Clear auxiliary fields to keep deterministic behavior when leafTable is reused.
	clear(leafTable[off+leafExtraOff : off+LeafRecordBytes])
}

// LeafKey returns the key for leafOrdinal.
// Caller must ensure leafTable is large enough.
func LeafKey(leafTable []byte, leafOrdinal uint32) uint64 {
	off := LeafRecordOffset(leafOrdinal)
	return readU64BE(leafTable[off : off+8])
}

// LeafValue returns the valueBytes for leafOrdinal.
// Caller must ensure leafTable is large enough.
func LeafValue(leafTable []byte, leafOrdinal uint32) [HashBytes]byte {
	off := LeafRecordOffset(leafOrdinal)
	var out [HashBytes]byte
	copy(out[:], leafTable[off+leafValueOff:off+leafValueOff+HashBytes])
	return out
}

// LeafExtraOffset returns the byte offset of extra field idx in the leaf record.
//
// idx is in [0..2] corresponding to extra1..extra3.
func LeafExtraOffset(leafOrdinal uint32, idx uint8) uint64 {
	if idx >= leafExtraFields {
		panic("urkle: leaf extra index out of range")
	}
	switch idx {
	case 0:
		return LeafRecordOffset(leafOrdinal) + leafExtra1Off
	case 1:
		return LeafRecordOffset(leafOrdinal) + leafExtra2Off
	case 2:
		return LeafRecordOffset(leafOrdinal) + leafExtra3Off
	default:
		panic("urkle: leaf extra index out of range")
	}
}

// LeafExtra returns the extra field bytes (32) for leafOrdinal at idx.
//
// idx is in [0..2] corresponding to extra1..extra3.
// Caller must ensure leafTable is large enough.
func LeafExtra(leafTable []byte, leafOrdinal uint32, idx uint8) [HashBytes]byte {
	var out [HashBytes]byte
	switch idx {
	case 0:
		off := LeafExtraOffset(leafOrdinal, idx)
		copy(out[:leafExtra1Bytes], leafTable[off:off+leafExtra1Bytes])
		// remaining bytes are zero
	default:
		off := LeafExtraOffset(leafOrdinal, idx)
		copy(out[:], leafTable[off:off+HashBytes])
	}
	return out
}

// LeafSetExtra stores extra bytes into the extra field idx for leafOrdinal.
//
// idx is in [0..2] corresponding to extra1..extra3.
// Caller must ensure leafTable is large enough.
//
// extra may be <= 32 bytes; any remaining bytes are zero-filled.
func LeafSetExtra(leafTable []byte, leafOrdinal uint32, idx uint8, extra []byte) {
	if len(extra) > HashBytes {
		panic("urkle: extra field too large")
	}
	switch idx {
	case 0:
		// extra1 stores only 24 bytes; any remaining bytes are discarded.
		off := LeafExtraOffset(leafOrdinal, idx)
		dst := leafTable[off : off+leafExtra1Bytes]
		clear(dst)
		if len(extra) > leafExtra1Bytes {
			extra = extra[:leafExtra1Bytes]
		}
		copy(dst, extra)
	case 1, 2:
		off := LeafExtraOffset(leafOrdinal, idx)
		dst := leafTable[off : off+HashBytes]
		clear(dst)
		copy(dst, extra)
	default:
		panic("urkle: leaf extra index out of range")
	}
}
