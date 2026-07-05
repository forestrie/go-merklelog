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

// MBitsV1 returns mBits64 = bitsPerElement * leafCount with no overflow
// checks.
//
// Callers are fully responsible for validating inputs and the result,
// including (when relevant to the call site):
//   - leafCount > 0
//   - bitsPerElement > 0 and within any desired range (for example,
//     via CheckBPE)
//   - detecting uint64 overflow in the product when it matters; for
//     leafCount > 0, callers can confirm that
//     mBits64/leafCount == bitsPerElement before downcasting or using
//     mBits64 for sizing.
//
// Note: MBitsSafeCast only checks that mBits64 fits in uint32; it does
// not detect uint64 wraparound of bitsPerElement * leafCount.
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
