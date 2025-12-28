package urkle

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNodeCountMaxAndBytesHelpers(t *testing.T) {
	require.Equal(t, uint64(0), NodeCountMax(0))
	require.Equal(t, uint64(1), NodeCountMax(1))
	require.Equal(t, uint64(9), NodeCountMax(5))

	leafCount := uint64(10)
	require.Equal(t, leafCount*LeafRecordBytes, LeafTableBytes(leafCount))
	require.Equal(t, NodeCountMax(leafCount)*NodeRecordBytes, NodeStoreBytes(leafCount))
}

func TestCheckLeafCount(t *testing.T) {
	max := uint64(^uint32(0))
	require.NoError(t, CheckLeafCount(max))

	err := CheckLeafCount(max + 1)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrLeafOrdinalDoesNotFit)
}

func TestLeafOrdinalBits(t *testing.T) {
	cases := []struct {
		leafCount uint64
		bits      uint8
	}{
		{0, 0},
		{1, 0},
		{2, 1},
		{3, 2},
		{4, 2},
		{5, 3},
		{8, 3},
		{9, 4},
	}

	for _, tc := range cases {
		got := LeafOrdinalBits(tc.leafCount)
		require.Equalf(t, tc.bits, got, "leafCount=%d", tc.leafCount)
	}
}

func TestLeafCountForMassifHeightAndCheckMassifHeightFits(t *testing.T) {
	require.Equal(t, uint64(0), LeafCountForMassifHeight(0))
	require.Equal(t, uint64(1), LeafCountForMassifHeight(1))
	require.Equal(t, uint64(2), LeafCountForMassifHeight(2))
	require.Equal(t, uint64(4), LeafCountForMassifHeight(3))

	// With 1-byte ordinals we can represent up to 2^8 leaves.
	require.NoError(t, CheckMassifHeightFitsLeafOrdinalBytes(9, 1)) // 2^8 leaves

	// Height high enough that N > 2^(8*ordinalBytes) should fail.
	// Use a relatively small value to keep the numbers comprehensible.
	maxLeavesFor1Byte := uint64(1) << 8
	require.Equal(t, maxLeavesFor1Byte, LeafCountForMassifHeight(9))

	err := CheckMassifHeightFitsLeafOrdinalBytes(10, 1) // 2^9 leaves > 2^8
	require.Error(t, err)
	require.ErrorIs(t, err, ErrLeafOrdinalDoesNotFit)
}

func TestCheckMassifHeight_LeafOrdinalCapacity(t *testing.T) {
	// With LeafOrdinalBytes == 4 and uint32-backed counters, the effective
	// leaf capacity per massif is 2^32-1, so massifHeight <= 32 is allowed
	// and massifHeight == 33 (N == 2^32) is rejected.
	require.NoError(t, CheckMassifHeight(32))

	err := CheckMassifHeight(33)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrLeafOrdinalDoesNotFit)
}

func TestLeafCountForMassifHeight_DoesNotOverflow(t *testing.T) {
	// Very large heights should still behave consistently and not panic.
	for h := uint8(1); h < 64; h++ {
		_ = LeafCountForMassifHeight(h)
	}

	// Height 64 would shift by 63, which is still defined; just assert it
	// does not overflow into zero.
	c := LeafCountForMassifHeight(64)
	require.NotEqual(t, uint64(0), c)
	require.LessOrEqual(t, c, uint64(math.MaxUint64))
}
