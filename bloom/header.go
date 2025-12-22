package bloom

import "bytes"

// DecodeHeaderV1 decodes a V1 header from region.
//
// ok=false indicates the region is zero-filled / uninitialized.
func DecodeHeaderV1(region []byte) (h HeaderV1, ok bool, err error) {
	if len(region) < HeaderBytesV1 {
		return HeaderV1{}, false, ErrBadRegionSize
	}

	if bytes.Equal(region[0:4], []byte{0, 0, 0, 0}) {
		return HeaderV1{}, false, nil
	}

	if string(region[0:4]) != MagicV1 {
		return HeaderV1{}, false, ErrBadMagic
	}
	if region[4] != VersionV1 {
		return HeaderV1{}, false, ErrBadVersion
	}

	h.BitOrder = region[5]
	h.K = region[6]
	filters := region[7]
	h.MBits = readU32BE(region[8:12])
	h.NInserted = readU32BE(region[12:16])

	if filters != Filters {
		return HeaderV1{}, false, ErrBadFilters
	}
	if h.BitOrder != BitOrderLSB0 {
		return HeaderV1{}, false, ErrBadBitOrder
	}
	if h.K == 0 {
		return HeaderV1{}, false, ErrBadK
	}
	if h.MBits == 0 {
		return HeaderV1{}, false, ErrBadMBits
	}

	return h, true, nil
}

// EncodeHeaderV1 writes a V1 header into region.
func EncodeHeaderV1(region []byte, h HeaderV1) error {
	if len(region) < HeaderBytesV1 {
		return ErrBadRegionSize
	}
	if h.BitOrder != BitOrderLSB0 {
		return ErrBadBitOrder
	}
	if h.K == 0 {
		return ErrBadK
	}
	if h.MBits == 0 {
		return ErrBadMBits
	}

	copy(region[0:4], []byte(MagicV1))
	region[4] = VersionV1
	region[5] = h.BitOrder
	region[6] = h.K
	region[7] = Filters
	writeU32BE(region[8:12], h.MBits)
	writeU32BE(region[12:16], h.NInserted)
	clear(region[16:HeaderBytesV1])
	return nil
}

