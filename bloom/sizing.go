package bloom

// CheckBPE validates bitsPerElement for safe sizing computations.
func CheckBPE(bitsPerElement uint64) error {
	if bitsPerElement == 0 {
		return ErrBadMBits
	}
	// Caller wants bitsPerElement constrained to a uint32-compatible range.
	if bitsPerElement > uint64(^uint32(0)) {
		return ErrMBitsOverflow
	}
	return nil
}

// MBitsV1 returns mBits64 = bitsPerElement * leafCount.
//
// The caller is responsible for ensuring:
//   - leafCount > 0
//   - bitsPerElement > 0
//   - bitsPerElement <= uint64(^uint32(0))
//
// CheckBPE can be used to check these conditions.
func MBitsV1(leafCount uint64, bitsPerElement uint64) uint64 {
	return bitsPerElement * leafCount
}

// MBitsSafeCast returns mBits as uint32, or 0 if it is not safe to downcast.
func MBitsSafeCast(mBits64 uint64) uint32 {
	if mBits64 == 0 || mBits64 > uint64(^uint32(0)) {
		return 0
	}
	return uint32(mBits64)
}

// BitsetBytesV1 returns ceil(mBits/8).
func BitsetBytesV1(mBits uint32) uint32 {
	return (mBits + 7) / 8
}

// RegionBytesV1 returns the required byte length for a 4-way BloomRegion given mBits:
//
//	HeaderBytesV1 + 4*ceil(mBits/8)
func RegionBytesV1(mBits uint32) uint64 {
	bitsetBytes := uint64(BitsetBytesV1(mBits))

	// total = header + filters*bitsetBytes
	total := uint64(HeaderBytesV1) + uint64(Filters)*bitsetBytes
	return total
}

func filterBitsetOffV1(filterIdx uint8, bitsetBytes uint32) (uint32, error) {
	if filterIdx >= Filters {
		return 0, ErrBadFilterIndex
	}
	return uint32(HeaderBytesV1) + uint32(filterIdx)*bitsetBytes, nil
}
