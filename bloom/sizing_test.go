package bloom

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSizingV1(t *testing.T) {
	require.NoError(t, CheckBPE(10))
	mBits64 := MBitsV1(1, 10)
	require.Equal(t, uint64(10), mBits64)
	mBits := MBitsSafeCast(mBits64)
	require.Equal(t, uint32(10), mBits)
	require.Equal(t, uint32(2), BitsetBytesV1(mBits))

	total := RegionBytesV1(mBits)
	require.Equal(t, uint64(HeaderBytesV1+Filters*2), total)

	mBits2 := MBitsSafeCast(MBitsV1(8, 8)) // mBits=64, bitsetBytes=8, total=32+32=64
	require.Equal(t, uint32(64), mBits2)
	total = RegionBytesV1(mBits2)
	require.Equal(t, uint64(64), total)
}

func TestSizingV1_MBbitsSafeCast(t *testing.T) {
	require.Equal(t, uint32(0), MBitsSafeCast(0))
	require.Equal(t, uint32(0), MBitsSafeCast(uint64(^uint32(0))+1))
	require.Equal(t, uint32(^uint32(0)), MBitsSafeCast(uint64(^uint32(0))))
}

func TestCheckBPE(t *testing.T) {
	require.ErrorIs(t, CheckBPE(0), ErrBadMBits)
	require.ErrorIs(t, CheckBPE(uint64(^uint32(0))+1), ErrMBitsOverflow)
}
