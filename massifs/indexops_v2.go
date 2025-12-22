package massifs

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/forestrie/go-merklelog/bloom"
	"github.com/forestrie/go-merklelog/massifs/snowflakeid"
	"github.com/forestrie/go-merklelog/urkle"
)

const (
	startHeaderWordBytes = ValueBytes
	startHeaderWordCount = StartHeaderSize / startHeaderWordBytes
)

func startHeaderWordRange(word uint8) (start, end uint64, err error) {
	if word >= startHeaderWordCount {
		return 0, 0, fmt.Errorf("start header word out of range: %d", word)
	}
	start = uint64(word) * startHeaderWordBytes
	end = start + startHeaderWordBytes
	return start, end, nil
}

func isAllZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// UrkleRootHash returns the stored per-massif Urkle root hash (if present).
//
// ok=false indicates the field is all-zero / unset.
//
// NOTE: The returned slice aliases the underlying massif buffer (`mc.Data`).
// Callers MUST treat it as read-only and MUST NOT retain it across operations
// that may reallocate `mc.Data` (e.g., appends).
func (mc MassifContext) UrkleRootHash() (root []byte, ok bool, err error) {
	start, end, err := startHeaderWordRange(1)
	if err != nil {
		return nil, false, err
	}
	if end > uint64(len(mc.Data)) {
		return nil, false, fmt.Errorf("start header out of range: end=%d len=%d", end, len(mc.Data))
	}
	raw := mc.Data[start:end]
	if isAllZero(raw) {
		return nil, false, nil
	}
	return raw, true, nil
}

// SetUrkleRootHash stores the per-massif Urkle root hash in start-header reserved word1.
func (mc *MassifContext) SetUrkleRootHash(root []byte) error {
	if len(root) != ValueBytes {
		return fmt.Errorf("root must be %d bytes", ValueBytes)
	}
	start, end, err := startHeaderWordRange(1)
	if err != nil {
		return err
	}
	if end > uint64(len(mc.Data)) {
		return fmt.Errorf("start header out of range: end=%d len=%d", end, len(mc.Data))
	}
	copy(mc.Data[start:end], root)
	return nil
}

// NextIDTimestamp generates the next idtimestamp, retrying on overload and ensuring
// it is strictly greater than the last idtimestamp recorded in this massif context.
func (mc *MassifContext) NextIDTimestamp(ctx context.Context, st *snowflakeid.IDState) (uint64, error) {
	if st == nil {
		return 0, fmt.Errorf("id state is required")
	}

	// Ensure strict monotonicity across restarts by comparing to the persisted last id.
	last := mc.GetLastIDTimestamp()

	for {
		id, err := st.NextID()
		if err == nil && id > last {
			return id, nil
		}

		if err != nil && !errors.Is(err, snowflakeid.ErrOverloaded) {
			return 0, err
		}

		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
}

func (mc MassifContext) requireV2Index() error {
	if mc.Start.Version != MassifCurrentVersion {
		return fmt.Errorf("unsupported massif version %d (need %d)", mc.Start.Version, MassifCurrentVersion)
	}
	if mc.Start.MassifHeight == 0 {
		return fmt.Errorf("invalid massifHeight=0")
	}
	return nil
}

// BloomRegion returns a contiguous view of the in-place BloomRegion (header+bitsets).
func (mc MassifContext) BloomRegion() ([]byte, error) {
	if err := mc.requireV2Index(); err != nil {
		return nil, err
	}

	leafCount := urkle.LeafCountForMassifHeight(mc.Start.MassifHeight)
	mBits := bloom.MBitsSafeCast(bloom.MBitsV1(leafCount, BloomBitsPerElementV1))
	if mBits == 0 {
		return nil, bloom.ErrMBitsOverflow
	}
	regionBytes := bloom.RegionBytesV1(mBits)

	start := mc.IndexHeaderStart()
	end := start + regionBytes
	if end > uint64(len(mc.Data)) {
		return nil, fmt.Errorf("bloom region exceeds buffer: end=%d len=%d", end, len(mc.Data))
	}
	return mc.Data[start:end], nil
}

// UrkleFrontierRegion returns the in-place, fixed-size Urkle frontier snapshot region.
func (mc MassifContext) UrkleFrontierRegion() ([]byte, error) {
	if err := mc.requireV2Index(); err != nil {
		return nil, err
	}

	leafCount := urkle.LeafCountForMassifHeight(mc.Start.MassifHeight)
	mBits := bloom.MBitsSafeCast(bloom.MBitsV1(leafCount, BloomBitsPerElementV1))
	if mBits == 0 {
		return nil, bloom.ErrMBitsOverflow
	}
	bloomRegionBytes := bloom.RegionBytesV1(mBits)

	start := mc.IndexHeaderStart() + bloomRegionBytes
	end := start + uint64(urkle.FrontierStateV1Bytes)
	if end > uint64(len(mc.Data)) {
		return nil, fmt.Errorf("urkle frontier exceeds buffer: end=%d len=%d", end, len(mc.Data))
	}
	return mc.Data[start:end], nil
}

func (mc MassifContext) urkleLeafCountV2() uint64 {
	return urkle.LeafCountForMassifHeight(mc.Start.MassifHeight)
}

// UrkleLeafTableRegion returns the in-place Urkle leaf table region.
func (mc MassifContext) UrkleLeafTableRegion() ([]byte, error) {
	if err := mc.requireV2Index(); err != nil {
		return nil, err
	}

	leafCount := mc.urkleLeafCountV2()

	// NOTE: We recompute offsets directly to avoid depending on slice lengths from other regions.
	mBits := bloom.MBitsSafeCast(bloom.MBitsV1(leafCount, BloomBitsPerElementV1))
	if mBits == 0 {
		return nil, bloom.ErrMBitsOverflow
	}
	bloomRegionBytes := bloom.RegionBytesV1(mBits)
	frontierStart := mc.IndexHeaderStart() + bloomRegionBytes
	leafTableStart := frontierStart + uint64(urkle.FrontierStateV1Bytes)
	leafTableEnd := leafTableStart + urkle.LeafTableBytes(leafCount)
	if leafTableEnd > uint64(len(mc.Data)) {
		return nil, fmt.Errorf("urkle leaf table exceeds buffer: end=%d len=%d", leafTableEnd, len(mc.Data))
	}
	return mc.Data[leafTableStart:leafTableEnd], nil
}

// UrkleNodeStoreRegion returns the in-place Urkle node store region.
func (mc MassifContext) UrkleNodeStoreRegion() ([]byte, error) {
	if err := mc.requireV2Index(); err != nil {
		return nil, err
	}

	leafCount := mc.urkleLeafCountV2()
	mBits := bloom.MBitsSafeCast(bloom.MBitsV1(leafCount, BloomBitsPerElementV1))
	if mBits == 0 {
		return nil, bloom.ErrMBitsOverflow
	}
	bloomRegionBytes := bloom.RegionBytesV1(mBits)
	frontierStart := mc.IndexHeaderStart() + bloomRegionBytes
	leafTableStart := frontierStart + uint64(urkle.FrontierStateV1Bytes)
	nodeStoreStart := leafTableStart + urkle.LeafTableBytes(leafCount)
	nodeStoreEnd := nodeStoreStart + urkle.NodeStoreBytes(leafCount)
	if nodeStoreEnd > uint64(len(mc.Data)) {
		return nil, fmt.Errorf("urkle node store exceeds buffer: end=%d len=%d", nodeStoreEnd, len(mc.Data))
	}
	return mc.Data[nodeStoreStart:nodeStoreEnd], nil
}

// UpdateBloomFilters updates any combination of the 4 parallel bloom filters based on extraData.
//
// - Filter 0 is always updated:
//   - if extraData[0] is nil or not provided, valueBytes is inserted
//   - otherwise extraData[0] is inserted
//
// - Filters 1..3 are updated only when the corresponding extraData[i] is provided and non-nil.
//
// Each inserted element must be exactly 32 bytes.
func (mc *MassifContext) UpdateBloomFilters(valueBytes []byte, extraData ...[]byte) error {
	if err := mc.requireV2Index(); err != nil {
		return err
	}
	if len(valueBytes) != ValueBytes {
		return fmt.Errorf("valueBytes must be %d bytes", ValueBytes)
	}

	leafCount := urkle.LeafCountForMassifHeight(mc.Start.MassifHeight)

	region, err := mc.BloomRegion()
	if err != nil {
		return err
	}

	// Ensure initialized (should already be for freshly-created massifs).
	if _, ok, err := bloom.DecodeHeaderV1(region); err != nil {
		return err
	} else if !ok {
		if err := bloom.InitV1(region, leafCount, BloomBitsPerElementV1, BloomKV1); err != nil {
			return err
		}
	}

	// Filter 0.
	elem0 := valueBytes
	if len(extraData) > 0 && extraData[0] != nil {
		elem0 = extraData[0]
	}
	if err := bloom.InsertV1(region, 0, elem0); err != nil {
		return err
	}

	// Filters 1..3.
	for filterIdx := uint8(1); filterIdx < bloom.Filters; filterIdx++ {
		i := int(filterIdx)
		if len(extraData) <= i || extraData[i] == nil {
			continue
		}
		if err := bloom.InsertV1(region, filterIdx, extraData[i]); err != nil {
			return err
		}
	}

	return nil
}

// InsertUrkleMonotone inserts (key,valueBytes) into the v2 Urkle index, persists the frontier,
// and stores up to 3 auxiliary extra fields in the leaf table record.
//
// extraData semantics:\n
// - extraData[0] is reserved for bloom0 override and is NOT stored in the leaf record.\n
// - extraData[1], extraData[2], extraData[3] (if provided and non-nil) are stored as extra1..extra3.\n
func (mc *MassifContext) InsertUrkleMonotone(key uint64, valueBytes []byte, extraData ...[]byte) (uint32, error) {
	if err := mc.requireV2Index(); err != nil {
		return 0, err
	}
	if len(valueBytes) != ValueBytes {
		return 0, fmt.Errorf("valueBytes must be %d bytes", ValueBytes)
	}

	leafTable, err := mc.UrkleLeafTableRegion()
	if err != nil {
		return 0, err
	}
	nodeStore, err := mc.UrkleNodeStoreRegion()
	if err != nil {
		return 0, err
	}
	frontier, err := mc.UrkleFrontierRegion()
	if err != nil {
		return 0, err
	}

	b, err := urkle.NewBuilderFromFrontier(sha256.New(), leafTable, nodeStore, frontier)
	if err != nil {
		return 0, err
	}

	leafOrdinal, err := b.InsertMonotone(key, valueBytes)
	if err != nil {
		return 0, err
	}

	// Store the last 3 extra fields (skip the first).
	for i := 1; i <= 3; i++ {
		if len(extraData) <= i || extraData[i] == nil {
			continue
		}
		if len(extraData[i]) > ValueBytes {
			return 0, fmt.Errorf("extraData[%d] too large: %d", i, len(extraData[i]))
		}
		urkle.LeafSetExtra(leafTable, leafOrdinal, uint8(i-1), extraData[i])
	}

	// Persist frontier for resumption.
	if err := b.SaveFrontier(frontier); err != nil {
		return 0, err
	}

	// If this insertion fills the leaf capacity, finalize and store the root hash.
	leafCount := mc.urkleLeafCountV2()
	if leafCount > uint64(^uint32(0)) {
		return 0, fmt.Errorf("leafCount does not fit uint32")
	}
	if uint64(leafOrdinal)+1 == leafCount {
		_, rootHash, err := b.Finalize()
		if err != nil {
			return 0, err
		}
		// Save the finalized frontier (Pending becomes the root, Depth=0).
		if err := b.SaveFrontier(frontier); err != nil {
			return 0, err
		}
		if err := mc.SetUrkleRootHash(rootHash[:]); err != nil {
			return 0, err
		}
	}

	return leafOrdinal, nil
}

// IndexLeaf updates the v2 index structures for a newly appended MMR leaf:
//   - inserts (idtimestamp -> valueBytes) into the Urkle trie\n
//   - updates bloom filters according to extraData.\n
func (mc *MassifContext) IndexLeaf(idTimestamp uint64, valueBytes []byte, extraData ...[]byte) error {
	leafOrdinal, err := mc.InsertUrkleMonotone(idTimestamp, valueBytes, extraData...)
	if err != nil {
		return err
	}

	// Best-effort consistency check: leafOrdinal should match the just-appended leaf index.
	if mc.MassifLeafCount() > 0 {
		want := uint32(mc.MassifLeafCount() - 1)
		if leafOrdinal != want {
			return fmt.Errorf("urkle leaf ordinal mismatch: got=%d want=%d", leafOrdinal, want)
		}
	}

	return mc.UpdateBloomFilters(valueBytes, extraData...)
}
