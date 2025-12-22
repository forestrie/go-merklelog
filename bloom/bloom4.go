package bloom

import (
	"crypto/sha256"
)

const bloomDomainV1 = 0xB0

// InitV1 initializes a zero-filled region with a BloomHeaderV1.
//
// The caller must allocate region with at least RegionBytesV1(mBits), where:
//
//	mBits = uint32(bitsPerElement * leafCount)
func InitV1(region []byte, leafCount uint64, bitsPerElement uint64, k uint8) error {
	if leafCount == 0 || bitsPerElement == 0 {
		return ErrBadMBits
	}
	if err := CheckBPE(bitsPerElement); err != nil {
		return err
	}
	mBits := MBitsSafeCast(MBitsV1(leafCount, bitsPerElement))
	if mBits == 0 {
		return ErrMBitsOverflow
	}
	bitsetBytes := BitsetBytesV1(mBits)
	need := uint64(HeaderBytesV1) + uint64(Filters)*uint64(bitsetBytes)
	if uint64(len(region)) < need {
		return ErrBadRegionSize
	}

	// Ensure clean initialization even if region is reused.
	clear(region[:need])

	return EncodeHeaderV1(region, HeaderV1{
		BitOrder:  BitOrderLSB0,
		K:         k,
		MBits:     mBits,
		NInserted: 0,
	})
}

// InsertV1 inserts elem into filterIdx and increments NInserted in the header.
func InsertV1(region []byte, filterIdx uint8, elem []byte) error {
	if filterIdx >= Filters {
		return ErrBadFilterIndex
	}
	if len(elem) != ValueBytes {
		return ErrBadElemSize
	}

	h, ok, err := DecodeHeaderV1(region)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotInitialized
	}

	bitsetBytes := BitsetBytesV1(h.MBits)
	off, err := filterBitsetOffV1(filterIdx, bitsetBytes)
	if err != nil {
		return err
	}
	end := uint64(off) + uint64(bitsetBytes)
	if uint64(len(region)) < end {
		return ErrBadRegionSize
	}
	bitset := region[off : off+bitsetBytes]

	h1, h2 := hashPairV1(filterIdx, elem)
	setBitsLSB0(bitset, uint64(h.MBits), h.K, h1, h2)

	// Update optional counter.
	h.NInserted++
	return EncodeHeaderV1(region, h)
}

// MaybeContainsV1 checks membership for elem in filterIdx.
//
// Returns (false,nil) if the filter says "definitely not present".
// Returns (true,nil) if the filter says "maybe present".
func MaybeContainsV1(region []byte, filterIdx uint8, elem []byte) (bool, error) {
	if filterIdx >= Filters {
		return false, ErrBadFilterIndex
	}
	if len(elem) != ValueBytes {
		return false, ErrBadElemSize
	}

	h, ok, err := DecodeHeaderV1(region)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, ErrNotInitialized
	}

	bitsetBytes := BitsetBytesV1(h.MBits)
	off, err := filterBitsetOffV1(filterIdx, bitsetBytes)
	if err != nil {
		return false, err
	}
	end := uint64(off) + uint64(bitsetBytes)
	if uint64(len(region)) < end {
		return false, ErrBadRegionSize
	}
	bitset := region[off : off+bitsetBytes]

	h1, h2 := hashPairV1(filterIdx, elem)
	return testBitsLSB0(bitset, uint64(h.MBits), h.K, h1, h2), nil
}

func hashPairV1(filterIdx uint8, elem32 []byte) (h1 uint64, h2 uint64) {
	// SHA-256( 0xB0 || filterIdx || elem32 )
	var buf [1 + 1 + ValueBytes]byte
	buf[0] = bloomDomainV1
	buf[1] = filterIdx
	copy(buf[2:], elem32)
	sum := sha256.Sum256(buf[:])
	h1 = readU64BE(sum[0:8])
	h2 = readU64BE(sum[8:16])
	if h2 == 0 {
		h2 = 1
	}
	return h1, h2
}

func setBitsLSB0(bitset []byte, mBits uint64, k uint8, h1, h2 uint64) {
	for i := uint64(0); i < uint64(k); i++ {
		j := (h1 + i*h2) % mBits
		byteIdx := j >> 3
		bit := uint8(j & 7)
		bitset[byteIdx] |= (1 << bit)
	}
}

func testBitsLSB0(bitset []byte, mBits uint64, k uint8, h1, h2 uint64) bool {
	for i := uint64(0); i < uint64(k); i++ {
		j := (h1 + i*h2) % mBits
		byteIdx := j >> 3
		bit := uint8(j & 7)
		if (bitset[byteIdx] & (1 << bit)) == 0 {
			return false
		}
	}
	return true
}
