package urkle

import "hash"

// HashLeaf computes:
//   H( 0x00 || key_be8 || leafOrdinal_be4 || valueBytes[32] )
func HashLeaf(hasher hash.Hash, key uint64, leafOrdinal uint32, valueBytes []byte) ([HashBytes]byte, error) {
	if len(valueBytes) != HashBytes {
		return [HashBytes]byte{}, ErrBadValueSize
	}
	hasher.Reset()
	_, _ = hasher.Write([]byte{0x00})
	HashWriteUint64(hasher, key)
	HashWriteUint32(hasher, leafOrdinal)
	_, _ = hasher.Write(valueBytes)

	var out [HashBytes]byte
	sum := hasher.Sum(out[:0])
	if len(sum) != HashBytes {
		return [HashBytes]byte{}, ErrBadHashSize
	}
	copy(out[:], sum)
	return out, nil
}

// HashBranch computes:
//   H( 0x01 || bit_u8 || leftHash[32] || rightHash[32] )
func HashBranch(hasher hash.Hash, bit uint8, left, right [HashBytes]byte) ([HashBytes]byte, error) {
	hasher.Reset()
	_, _ = hasher.Write([]byte{0x01, bit})
	_, _ = hasher.Write(left[:])
	_, _ = hasher.Write(right[:])

	var out [HashBytes]byte
	sum := hasher.Sum(out[:0])
	if len(sum) != HashBytes {
		return [HashBytes]byte{}, ErrBadHashSize
	}
	copy(out[:], sum)
	return out, nil
}


