package massifs

import (
	"fmt"

	"github.com/forestrie/go-merklelog/bloom"
	"github.com/forestrie/go-merklelog/urkle"
)

const (
	// BloomBitsPerElementV1 is the fixed sizing knob for the v2 massif BloomRegion.
	//
	// mBits = bitsPerElement * leafCount, per filter.
	BloomBitsPerElementV1 uint64 = 10

	// BloomKV1 is the number of hash-derived bit positions set per inserted element.
	//
	// For b=10, k≈round(0.693*b)=7.
	BloomKV1 uint8 = 7
)

// indexDataBytesV2 returns the byte size of the v2 index *data* region, excluding the fixed 32B index header.
//
// v2 index header (32B) is BloomHeaderV1, and the index data is:
//
//	bloom bitsets || urkle frontier || urkle leaf table || urkle node store
func indexDataBytesV2(leafCount uint64) (uint64, error) {
	// Bloom region bytes includes the 32B header; we exclude that here
	// because the massif index header is fixed 32B.
	mBits, err := bloomMBitsV1ForLeafCount(leafCount)
	if err != nil {
		return 0, err
	}
	bloomRegionBytes := bloom.RegionBytesV1(mBits)
	if bloomRegionBytes < uint64(bloom.HeaderBytesV1) {
		return 0, fmt.Errorf("bloom region too small: %d", bloomRegionBytes)
	}
	bloomBitsetsBytes := bloomRegionBytes - uint64(bloom.HeaderBytesV1)

	frontierBytes := uint64(urkle.FrontierStateV1Bytes)
	leafTableBytes := urkle.LeafTableBytes(leafCount)
	nodeStoreBytes := urkle.NodeStoreBytes(leafCount)

	total := bloomBitsetsBytes + frontierBytes + leafTableBytes + nodeStoreBytes
	// Basic overflow guard (uint64 add wrap).
	if total < bloomBitsetsBytes || total < frontierBytes || total < leafTableBytes || total < nodeStoreBytes {
		return 0, fmt.Errorf("index size overflow")
	}
	return total, nil
}

// bloomMBitsV1ForLeafCount computes the Bloom mBits for the given
// leafCount using the v2 index sizing knobs, and enforces both uint64
// and uint32 bounds.
func bloomMBitsV1ForLeafCount(leafCount uint64) (uint32, error) {
	mBits64 := bloom.MBitsV1(leafCount, BloomBitsPerElementV1)
	// Detect uint64 overflow in BloomBitsPerElementV1 * leafCount.
	if leafCount > 0 && mBits64/leafCount != BloomBitsPerElementV1 {
		return 0, bloom.ErrMBitsOverflow
	}
	mBits := bloom.MBitsSafeCast(mBits64)
	if mBits == 0 {
		return 0, bloom.ErrMBitsOverflow
	}
	return mBits, nil
}
