package massifs

import (
	"fmt"

	"github.com/forestrie/go-merklelog/bloom"
	"github.com/forestrie/go-merklelog/urkle"
)

// initIndexV2 initializes v2 index regions in-place.
//
// It is safe to call this only when creating a new massif, where the index region is zero-filled.
func (mc *MassifContext) initIndexV2() error {
	if mc.Start.Version != MassifCurrentVersion {
		return nil
	}

	if mc.Start.MassifHeight == 0 {
		return fmt.Errorf("invalid massifHeight=0")
	}
	// massifHeight is one-based (h). Leaf capacity is N = 2^(h-1).
	leafCount := urkle.LeafCountForMassifHeight(mc.Start.MassifHeight)

	mBits := bloom.MBitsSafeCast(bloom.MBitsV1(leafCount, BloomBitsPerElementV1))
	if mBits == 0 {
		return bloom.ErrMBitsOverflow
	}
	regionBytes := bloom.RegionBytesV1(mBits)

	start := mc.IndexHeaderStart()
	end := start + regionBytes
	if end > uint64(len(mc.Data)) {
		return fmt.Errorf("bloom region exceeds buffer: end=%d len=%d", end, len(mc.Data))
	}
	region := mc.Data[start:end]

	// Initialize the bloom region header and clear bitsets.
	return bloom.InitV1(region, leafCount, BloomBitsPerElementV1, BloomKV1)
}
