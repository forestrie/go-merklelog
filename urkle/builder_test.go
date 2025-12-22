package urkle

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuilderInsertRejectsOutOfOrderAndDuplicate(t *testing.T) {
	leafCount := uint64(8)
	leafTable := make([]byte, LeafTableBytes(leafCount))
	nodeStore := make([]byte, NodeStoreBytes(leafCount))

	b, err := NewBuilder(sha256.New(), leafTable, nodeStore)
	require.NoError(t, err)

	var v [HashBytes]byte
	v[0] = 0xAA

	_, err = b.InsertMonotone(10, v[:])
	require.NoError(t, err)

	_, err = b.InsertMonotone(20, v[:])
	require.NoError(t, err)

	// Duplicate
	_, err = b.InsertMonotone(20, v[:])
	require.ErrorIs(t, err, ErrDuplicateKey)

	// Out of order
	_, err = b.InsertMonotone(15, v[:])
	require.ErrorIs(t, err, ErrOutOfOrderKey)
}

func TestBuilderFrontierRoundTripResumeMatchesNoBoundaryBuild(t *testing.T) {
	keys := []uint64{1, 2, 3, 4, 5, 6}

	mkValue := func(k uint64) [HashBytes]byte {
		var v [HashBytes]byte
		v[0] = byte(k)
		v[1] = byte(k >> 8)
		return v
	}

	// Baseline: build in one go.
	{
		leafTable := make([]byte, LeafTableBytes(uint64(len(keys))))
		nodeStore := make([]byte, NodeStoreBytes(uint64(len(keys))))
		b, err := NewBuilder(sha256.New(), leafTable, nodeStore)
		require.NoError(t, err)

		for _, k := range keys {
			v := mkValue(k)
			_, err := b.InsertMonotone(k, v[:])
			require.NoError(t, err)
		}
		_, root1, err := b.Finalize()
		require.NoError(t, err)

		// Split build: persist frontier after 3 keys, resume, and finish.
		leafTable2 := make([]byte, LeafTableBytes(uint64(len(keys))))
		nodeStore2 := make([]byte, NodeStoreBytes(uint64(len(keys))))
		b2, err := NewBuilder(sha256.New(), leafTable2, nodeStore2)
		require.NoError(t, err)

		for _, k := range keys[:3] {
			v := mkValue(k)
			_, err := b2.InsertMonotone(k, v[:])
			require.NoError(t, err)
		}

		frontier := make([]byte, FrontierStateV1Bytes)
		require.NoError(t, b2.SaveFrontier(frontier))

		// Simulate reload from disk.
		leafTable3 := make([]byte, len(leafTable2))
		copy(leafTable3, leafTable2)
		nodeStore3 := make([]byte, len(nodeStore2))
		copy(nodeStore3, nodeStore2)

		b3, err := NewBuilderFromFrontier(sha256.New(), leafTable3, nodeStore3, frontier)
		require.NoError(t, err)

		for _, k := range keys[3:] {
			v := mkValue(k)
			_, err := b3.InsertMonotone(k, v[:])
			require.NoError(t, err)
		}
		_, root2, err := b3.Finalize()
		require.NoError(t, err)

		require.Equal(t, root1, root2)
	}
}


