package bloom

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func makeEncodedHeaderV1(t *testing.T) []byte {
	region := make([]byte, HeaderBytesV1)
	h := HeaderV1{
		BitOrder:  BitOrderLSB0,
		K:         7,
		MBits:     64,
		NInserted: 10,
	}
	require.NoError(t, EncodeHeaderV1(region, h))
	return region
}

func TestDecodeHeaderV1_UninitializedZeroRegion(t *testing.T) {
	region := make([]byte, HeaderBytesV1)

	h, ok, err := DecodeHeaderV1(region)
	require.NoError(t, err)
	require.False(t, ok)
	require.Equal(t, HeaderV1{}, h)
}

func TestDecodeHeaderV1_TooShort(t *testing.T) {
	region := make([]byte, HeaderBytesV1-1)

	_, ok, err := DecodeHeaderV1(region)
	require.ErrorIs(t, err, ErrBadRegionSize)
	require.False(t, ok)
}

func TestDecodeHeaderV1_ErrorVariants(t *testing.T) {
	mk := func(t *testing.T) []byte {
		return makeEncodedHeaderV1(t)
	}

	tests := []struct {
		name   string
		mutate func([]byte)
		want   error
	}{
		{
			name: "bad magic",
			mutate: func(b []byte) {
				copy(b[0:4], []byte("BAD!"))
			},
			want: ErrBadMagic,
		},
		{
			name: "bad version",
			mutate: func(b []byte) {
				b[4] = VersionV1 + 1
			},
			want: ErrBadVersion,
		},
		{
			name: "bad filters",
			mutate: func(b []byte) {
				b[7] = Filters + 1
			},
			want: ErrBadFilters,
		},
		{
			name: "bad bit order",
			mutate: func(b []byte) {
				b[5] = BitOrderLSB0 + 1
			},
			want: ErrBadBitOrder,
		},
		{
			name: "bad k",
			mutate: func(b []byte) {
				b[6] = 0
			},
			want: ErrBadK,
		},
		{
			name: "bad mBits",
			mutate: func(b []byte) {
				for i := 8; i < 12; i++ {
					b[i] = 0
				}
			},
			want: ErrBadMBits,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			region := mk(t)
			tc.mutate(region)

			_, ok, err := DecodeHeaderV1(region)
			require.ErrorIs(t, err, tc.want)
			require.False(t, ok)
		})
	}
}

func TestEncodeHeaderV1_ErrorVariants(t *testing.T) {
	// Too-small region.
	small := make([]byte, HeaderBytesV1-1)
	err := EncodeHeaderV1(small, HeaderV1{
		BitOrder: BitOrderLSB0,
		K:        1,
		MBits:    1,
	})
	require.ErrorIs(t, err, ErrBadRegionSize)

	region := make([]byte, HeaderBytesV1)

	// Bad bit order.
	err = EncodeHeaderV1(region, HeaderV1{
		BitOrder: BitOrderLSB0 + 1,
		K:        1,
		MBits:    1,
	})
	require.ErrorIs(t, err, ErrBadBitOrder)

	// Bad k.
	err = EncodeHeaderV1(region, HeaderV1{
		BitOrder: BitOrderLSB0,
		K:        0,
		MBits:    1,
	})
	require.ErrorIs(t, err, ErrBadK)

	// Bad mBits.
	err = EncodeHeaderV1(region, HeaderV1{
		BitOrder: BitOrderLSB0,
		K:        1,
		MBits:    0,
	})
	require.ErrorIs(t, err, ErrBadMBits)
}

func TestHeaderV1_EncodeDecodeRoundTrip(t *testing.T) {
	region := make([]byte, HeaderBytesV1)
	want := HeaderV1{
		BitOrder:  BitOrderLSB0,
		K:         5,
		MBits:     128,
		NInserted: 42,
	}

	require.NoError(t, EncodeHeaderV1(region, want))
	got, ok, err := DecodeHeaderV1(region)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, want, got)
}

func TestFilterBitsetOffV1_OffsetsAndBounds(t *testing.T) {
	bitsetBytes := uint32(8)

	off0, err := filterBitsetOffV1(0, bitsetBytes)
	require.NoError(t, err)
	require.Equal(t, uint32(HeaderBytesV1), off0)

	off1, err := filterBitsetOffV1(1, bitsetBytes)
	require.NoError(t, err)
	require.Equal(t, uint32(HeaderBytesV1)+bitsetBytes, off1)

	// Out-of-range filter index.
	_, err = filterBitsetOffV1(Filters, bitsetBytes)
	require.ErrorIs(t, err, ErrBadFilterIndex)
}

func TestBitOrderLSB0_SetAndTest(t *testing.T) {
	bitset := make([]byte, 1)
	mBits := uint64(8)
	k := uint8(2)

	// Choose h1 and h2 such that the probed bits are 3 and 0 in order.
	setBitsLSB0(bitset, mBits, k, 3, 5) // j0=3, j1=(3+5)%8=0

	// Bits 0 and 3 should be set in the first byte: 00001001b.
	require.Equal(t, byte(0x09), bitset[0])

	require.True(t, testBitsLSB0(bitset, mBits, k, 3, 5))
	// Different h2 should probe a different bit (4) which is not set.
	require.False(t, testBitsLSB0(bitset, mBits, k, 3, 1))
}
