package bloom

import "errors"

const (
	// ValueBytes is the fixed element width (Forestrie log value width).
	ValueBytes = 32

	// Filters is the number of parallel Bloom filters in this format.
	Filters uint8 = 4

	// HeaderBytesV1 is the fixed header size for BloomHeaderV1.
	HeaderBytesV1 = 32

	MagicV1   = "BLM1"
	VersionV1 uint8 = 1

	// BitOrderLSB0 means bit 0 is the least-significant bit of byte 0.
	BitOrderLSB0 uint8 = 0
)

var (
	ErrBadElemSize    = errors.New("bloom: element must be 32 bytes")
	ErrBadFilterIndex = errors.New("bloom: invalid filter index")
	ErrBadRegionSize  = errors.New("bloom: region buffer too small")
	ErrNotInitialized = errors.New("bloom: header not initialized")

	ErrBadMagic    = errors.New("bloom: header magic invalid")
	ErrBadVersion  = errors.New("bloom: header version invalid")
	ErrBadBitOrder = errors.New("bloom: header bitOrder unsupported")
	ErrBadK        = errors.New("bloom: header k invalid")
	ErrBadFilters  = errors.New("bloom: header filters invalid")
	ErrBadMBits    = errors.New("bloom: header mBits invalid")

	ErrMBitsOverflow = errors.New("bloom: mBits overflows supported range")
	ErrSizeOverflow  = errors.New("bloom: size computation overflow")
)

type HeaderV1 struct {
	BitOrder  uint8
	K         uint8
	MBits     uint32
	NInserted uint32
}


