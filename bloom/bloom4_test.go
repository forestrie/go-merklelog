package bloom

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBloomV1InsertAndQuery(t *testing.T) {
	leafCount := uint64(128)
	bitsPerElement := uint64(10)
	k := uint8(7)

	mBits := MBitsSafeCast(MBitsV1(leafCount, bitsPerElement))
	require.NotZero(t, mBits)
	total := RegionBytesV1(mBits)

	region := make([]byte, total)
	require.NoError(t, InitV1(region, leafCount, bitsPerElement, k))

	h, ok, err := DecodeHeaderV1(region)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, BitOrderLSB0, h.BitOrder)
	require.Equal(t, k, h.K)
	require.NotZero(t, h.MBits)
	require.Equal(t, uint32(0), h.NInserted)

	elem := func(b byte) []byte {
		x := make([]byte, ValueBytes)
		x[0] = b
		x[1] = b ^ 0x5A
		return x
	}

	// Empty filters are definitely-not-present for any element.
	ok0, err := MaybeContainsV1(region, 0, elem(1))
	require.NoError(t, err)
	require.False(t, ok0)

	// Insert into filter 0.
	require.NoError(t, InsertV1(region, 0, elem(1)))

	ok0, err = MaybeContainsV1(region, 0, elem(1))
	require.NoError(t, err)
	require.True(t, ok0)

	// Insert multiple elements into filter 2.
	for i := byte(0); i < 10; i++ {
		require.NoError(t, InsertV1(region, 2, elem(i)))
	}
	for i := byte(0); i < 10; i++ {
		ok, err := MaybeContainsV1(region, 2, elem(i))
		require.NoError(t, err)
		require.True(t, ok)
	}

	// NInserted is a best-effort counter; we increment per InsertV1 call.
	h2, ok, err := DecodeHeaderV1(region)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, uint32(1+10), h2.NInserted)
}

func TestBloomV1RejectsBadInputs(t *testing.T) {
	leafCount := uint64(8)
	bitsPerElement := uint64(8)
	k := uint8(5)

	mBits := MBitsSafeCast(MBitsV1(leafCount, bitsPerElement))
	require.NotZero(t, mBits)
	total := RegionBytesV1(mBits)

	region := make([]byte, total)
	require.NoError(t, InitV1(region, leafCount, bitsPerElement, k))

	// Bad filter index.
	err := InsertV1(region, 4, make([]byte, ValueBytes))
	require.ErrorIs(t, err, ErrBadFilterIndex)

	_, err = MaybeContainsV1(region, 4, make([]byte, ValueBytes))
	require.ErrorIs(t, err, ErrBadFilterIndex)

	// Bad element size.
	err = InsertV1(region, 0, make([]byte, ValueBytes-1))
	require.ErrorIs(t, err, ErrBadElemSize)

	_, err = MaybeContainsV1(region, 0, make([]byte, ValueBytes+1))
	require.ErrorIs(t, err, ErrBadElemSize)
}

func TestBloomV1RejectsUninitializedRegion(t *testing.T) {
	leafCount := uint64(8)
	bitsPerElement := uint64(8)

	mBits := MBitsSafeCast(MBitsV1(leafCount, bitsPerElement))
	require.NotZero(t, mBits)
	total := RegionBytesV1(mBits)

	region := make([]byte, total) // remains all-zero

	_, err := MaybeContainsV1(region, 0, make([]byte, ValueBytes))
	require.ErrorIs(t, err, ErrNotInitialized)

	err = InsertV1(region, 0, make([]byte, ValueBytes))
	require.ErrorIs(t, err, ErrNotInitialized)
}
