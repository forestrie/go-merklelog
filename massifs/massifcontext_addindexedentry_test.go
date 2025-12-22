package massifs

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/forestrie/go-merklelog/bloom"
	"github.com/forestrie/go-merklelog/urkle"
	"github.com/stretchr/testify/require"
)

func TestMassifContext_AddIndexedEntry_DoesNotMutateIndexRegions(t *testing.T) {
	mc, err := CreateFirstMassifContext(context.Background(), 1, 3)
	require.NoError(t, err)

	bloomBefore, err := mc.BloomRegion()
	require.NoError(t, err)
	bloomSnap := append([]byte(nil), bloomBefore...)

	frontierBefore, err := mc.UrkleFrontierRegion()
	require.NoError(t, err)
	frontierSnap := append([]byte(nil), frontierBefore...)

	leafTableBefore, err := mc.UrkleLeafTableRegion()
	require.NoError(t, err)
	leafTableSnap := append([]byte(nil), leafTableBefore...)

	nodeStoreBefore, err := mc.UrkleNodeStoreRegion()
	require.NoError(t, err)
	nodeStoreSnap := append([]byte(nil), nodeStoreBefore...)

	leaf := sha256.Sum256([]byte("mmr-leaf"))
	_, err = mc.AddIndexedEntry(leaf[:])
	require.NoError(t, err)

	bloomAfter, err := mc.BloomRegion()
	require.NoError(t, err)
	require.Equal(t, bloomSnap, bloomAfter)

	frontierAfter, err := mc.UrkleFrontierRegion()
	require.NoError(t, err)
	require.Equal(t, frontierSnap, frontierAfter)

	leafTableAfter, err := mc.UrkleLeafTableRegion()
	require.NoError(t, err)
	require.Equal(t, leafTableSnap, leafTableAfter)

	nodeStoreAfter, err := mc.UrkleNodeStoreRegion()
	require.NoError(t, err)
	require.Equal(t, nodeStoreSnap, nodeStoreAfter)
}

func TestMassifContext_IndexLeaf_UpdatesUrkleAndBloom(t *testing.T) {
	mc, err := CreateFirstMassifContext(context.Background(), 1, 3)
	require.NoError(t, err)

	// Append first MMR leaf, then index it.
	leaf := sha256.Sum256([]byte("mmr-leaf"))
	_, err = mc.AddIndexedEntry(leaf[:])
	require.NoError(t, err)

	idTimestamp := uint64(0x0102030405060708)
	// valueBytes is the content-hash, which is stored directly in the trie (not the MMR leaf hash).
	valueBytes := sha256.Sum256([]byte("content-hash"))

	// extraData[0] overrides bloom0 element and is NOT stored in the Urkle leaf record.
	extra0 := make([]byte, ValueBytes)
	extra0[0] = 0xFF
	extra1 := make([]byte, ValueBytes)
	extra1[0] = 1
	extra1[1] = 2
	extra1[2] = 3
	var extra2 []byte // nil => no update / stored zeros
	extra3 := make([]byte, ValueBytes)
	extra3[0] = 9

	err = mc.IndexLeaf(idTimestamp, valueBytes[:], extra0, extra1, extra2, extra3)
	require.NoError(t, err)

	leafTable, err := mc.UrkleLeafTableRegion()
	require.NoError(t, err)
	require.Equal(t, idTimestamp, urkle.LeafKey(leafTable, 0))
	// Verify that the trie stores the content-hash directly in valueBytes.
	require.Equal(t, valueBytes, urkle.LeafValue(leafTable, 0))

	// Stored extras are the last 3 slices (extra1..extra3).
	e1 := urkle.LeafExtra(leafTable, 0, 0)
	require.Equal(t, byte(1), e1[0])
	require.Equal(t, byte(2), e1[1])
	require.Equal(t, byte(3), e1[2])

	require.Equal(t, [urkle.HashBytes]byte{}, urkle.LeafExtra(leafTable, 0, 1))

	e3 := urkle.LeafExtra(leafTable, 0, 2)
	require.Equal(t, byte(9), e3[0])

	// Bloom checks: inserted elements must be reported as maybe-present.
	region, err := mc.BloomRegion()
	require.NoError(t, err)

	var want0 [ValueBytes]byte
	want0[0] = 0xFF
	ok, err := bloom.MaybeContainsV1(region, 0, want0[:])
	require.NoError(t, err)
	require.True(t, ok)

	var want1 [ValueBytes]byte
	want1[0] = 1
	want1[1] = 2
	want1[2] = 3
	ok, err = bloom.MaybeContainsV1(region, 1, want1[:])
	require.NoError(t, err)
	require.True(t, ok)

	var want3 [ValueBytes]byte
	want3[0] = 9
	ok, err = bloom.MaybeContainsV1(region, 3, want3[:])
	require.NoError(t, err)
	require.True(t, ok)
}
