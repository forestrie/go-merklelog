package urkle

import (
	"crypto/sha256"
	"testing"

	"github.com/forestrie/go-merklelog/mmr"
	"github.com/stretchr/testify/require"
)

func TestIndexViewAndAPIs(t *testing.T) {
	hasher := sha256.New()

	// Small, fixed-capacity chunk.
	const massifHeight = uint8(4) // leafCount = 2^(4-1) = 8
	leafCount := LeafCountForMassifHeight(massifHeight)
	require.Equal(t, uint64(8), leafCount)

	leafTable := make([]byte, LeafTableBytes(leafCount))
	nodeStore := make([]byte, NodeStoreBytes(leafCount))

	b, err := NewBuilder(hasher, leafTable, nodeStore)
	require.NoError(t, err)

	// Insert a few monotone keys.
	keys := []uint64{10, 20, 30, 40, 50}
	var nextLeaf uint32
	for _, k := range keys {
		v := sha256.Sum256([]byte{byte(k)})
		_, err := b.InsertMonotone(k, v[:])
		require.NoError(t, err)
		nextLeaf++
	}
	rootRef, rootHash, err := b.Finalize()
	require.NoError(t, err)

	// Compose indexData as leafTable||nodeStore (as per API contract).
	indexData := append(append([]byte{}, leafTable...), nodeStore...)
	v, err := NewIndexViewFromMassifHeight(indexData, massifHeight)
	require.NoError(t, err)

	// LeafOrdinalKey16
	gotKey := LeafOrdinalKey16(v, 0, nextLeaf)
	require.Equal(t, keys[0], gotKey)
	require.Equal(t, uint64(0), LeafOrdinalKey16(v, uint16(nextLeaf), nextLeaf))

	// LeafOrdinalInclusionProof
	p, k, err := LeafOrdinalInclusionProof(v, 1, nextLeaf, rootRef)
	require.NoError(t, err)
	require.Equal(t, keys[1], k)
	ok, ord, _, err := VerifyInclusion(sha256.New(), rootHash, p)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, uint32(1), ord)

	// KeyLeafOrdinal / KeyMMRIndex
	gotOrd, err := KeyLeafOrdinal(v, rootRef, keys[3])
	require.NoError(t, err)
	require.Equal(t, uint16(3), gotOrd)

	firstLeafIndex := uint64(100)
	firstLeafMMRIndex := mmr.MMRIndex(firstLeafIndex)
	mmrIdx, err := KeyMMRIndex(v, rootRef, keys[3], firstLeafMMRIndex)
	require.NoError(t, err)
	require.Equal(t, mmr.MMRIndex(firstLeafIndex+3), mmrIdx)

	// ProveInclusionFromView / ProveExclusionFromView wrappers
	p2, err := ProveInclusionFromView(v, rootRef, keys[4])
	require.NoError(t, err)
	ok, _, _, err = VerifyInclusion(sha256.New(), rootHash, p2)
	require.NoError(t, err)
	require.True(t, ok)

	ex, err := ProveExclusionFromView(v, rootRef, 35)
	require.NoError(t, err)
	ok3, _, _, _, err := VerifyExclusion(sha256.New(), rootHash, ex)
	require.NoError(t, err)
	require.True(t, ok3)

	// KeyFields view
	fv := KeyFields(v, nextLeaf)
	require.Equal(t, uint32(len(keys)), fv.Count)
	require.Equal(t, uint64(LeafRecordBytes), fv.RecordBytes)
	require.Equal(t, uint64(0), fv.KeyOffset)
	require.Equal(t, uint64(8), fv.KeyBytes)
}
