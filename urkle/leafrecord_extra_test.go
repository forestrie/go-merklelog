package urkle

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLeafRecord_Extras(t *testing.T) {
	require.Equal(t, uint64(128), uint64(LeafRecordBytes))

	leafTable := make([]byte, LeafRecordBytes*2)

	var v [HashBytes]byte
	for i := range v {
		v[i] = 0xAA
	}

	LeafSet(leafTable, 1, 0x0102030405060708, v[:])
	require.Equal(t, uint64(0x0102030405060708), LeafKey(leafTable, 1))
	require.Equal(t, v, LeafValue(leafTable, 1))

	// Extras start zeroed.
	require.Equal(t, [HashBytes]byte{}, LeafExtra(leafTable, 1, 0))
	require.Equal(t, [HashBytes]byte{}, LeafExtra(leafTable, 1, 1))
	require.Equal(t, [HashBytes]byte{}, LeafExtra(leafTable, 1, 2))

	// Set extras with variable-length input; remainder must be zero.
	LeafSetExtra(leafTable, 1, 0, []byte{1, 2, 3})
	LeafSetExtra(leafTable, 1, 1, make([]byte, HashBytes))
	LeafSetExtra(leafTable, 1, 2, []byte{9})

	e0 := LeafExtra(leafTable, 1, 0)
	require.Equal(t, byte(1), e0[0])
	require.Equal(t, byte(2), e0[1])
	require.Equal(t, byte(3), e0[2])
	for i := 3; i < HashBytes; i++ {
		require.Equal(t, byte(0), e0[i])
	}

	e2 := LeafExtra(leafTable, 1, 2)
	require.Equal(t, byte(9), e2[0])
	for i := 1; i < HashBytes; i++ {
		require.Equal(t, byte(0), e2[i])
	}
}
