package urkle

import (
	"crypto/sha256"
	"testing"

	"github.com/forestrie/go-merklelog/mmr"
	"github.com/stretchr/testify/require"
)

func TestProofInclusionRoundTrip(t *testing.T) {
	keys := []uint64{10, 20, 30, 40, 50, 60, 70, 80}
	leafCount := uint64(len(keys))

	leafTable := make([]byte, LeafTableBytes(leafCount))
	nodeStore := make([]byte, NodeStoreBytes(leafCount))

	b, err := NewBuilder(sha256.New(), leafTable, nodeStore)
	require.NoError(t, err)

	wantVal := func(k uint64) [HashBytes]byte {
		var v [HashBytes]byte
		v[0] = byte(k)
		v[1] = byte(k >> 8)
		v[2] = byte(k >> 16)
		v[3] = byte(k >> 24)
		return v
	}

	wantOrdinal := map[uint64]uint32{}
	for i, k := range keys {
		v := wantVal(k)
		ord, err := b.InsertMonotone(k, v[:])
		require.NoError(t, err)
		wantOrdinal[k] = ord
		require.Equal(t, uint32(i), ord)
	}

	rootRef, rootHash, err := b.Finalize()
	require.NoError(t, err)
	require.NotEqual(t, NoRef, rootRef)
	checkNodeStoreInvariants(t, nodeStore, rootRef)

	for _, k := range keys {
		p, err := ProveInclusion(leafTable, nodeStore, rootRef, k)
		require.NoError(t, err)
		require.Equal(t, k, p.Key)
		require.Equal(t, wantOrdinal[k], p.LeafOrdinal)
		require.Equal(t, wantVal(k), p.Value)

		ok, gotOrdinal, gotVal, err := VerifyInclusion(sha256.New(), rootHash, p)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, wantOrdinal[k], gotOrdinal)
		require.Equal(t, wantVal(k), gotVal)
	}

	_, err = ProveInclusion(leafTable, nodeStore, rootRef, 15)
	require.ErrorIs(t, err, ErrKeyNotFound)
}

func TestProofExclusionRoundTrip(t *testing.T) {
	keys := []uint64{10, 20, 30, 40, 50}
	leafCount := uint64(len(keys))

	leafTable := make([]byte, LeafTableBytes(leafCount))
	nodeStore := make([]byte, NodeStoreBytes(leafCount))

	b, err := NewBuilder(sha256.New(), leafTable, nodeStore)
	require.NoError(t, err)

	mkVal := func(k uint64) [HashBytes]byte {
		var v [HashBytes]byte
		v[0] = byte(k)
		v[31] = byte(^k)
		return v
	}

	for _, k := range keys {
		v := mkVal(k)
		_, err := b.InsertMonotone(k, v[:])
		require.NoError(t, err)
	}

	rootRef, rootHash, err := b.Finalize()
	require.NoError(t, err)
	checkNodeStoreInvariants(t, nodeStore, rootRef)

	// Present key => exclusion proof must fail.
	_, err = ProveExclusion(leafTable, nodeStore, rootRef, 30)
	require.ErrorIs(t, err, ErrKeyPresent)

	missing := []uint64{
		5,  // below min
		15, // between 10 and 20
		60, // above max
	}

	for _, target := range missing {
		p, err := ProveExclusion(leafTable, nodeStore, rootRef, target)
		require.NoError(t, err)
		require.Equal(t, target, p.TargetKey)
		require.NotEqual(t, target, p.EncounteredKey)

		ok, gotEncKey, gotOrdinal, gotVal, err := VerifyExclusion(sha256.New(), rootHash, p)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, p.EncounteredKey, gotEncKey)
		require.Equal(t, p.LeafOrdinal, gotOrdinal)
		require.Equal(t, p.Value, gotVal)
	}
}

func TestVerifyInclusionFailsIfTampered(t *testing.T) {
	keys := []uint64{1, 2, 3, 4}
	leafCount := uint64(len(keys))

	leafTable := make([]byte, LeafTableBytes(leafCount))
	nodeStore := make([]byte, NodeStoreBytes(leafCount))

	b, err := NewBuilder(sha256.New(), leafTable, nodeStore)
	require.NoError(t, err)

	var v [HashBytes]byte
	v[0] = 0xA5

	for _, k := range keys {
		_, err := b.InsertMonotone(k, v[:])
		require.NoError(t, err)
	}

	rootRef, rootHash, err := b.Finalize()
	require.NoError(t, err)
	checkNodeStoreInvariants(t, nodeStore, rootRef)

	p, err := ProveInclusion(leafTable, nodeStore, rootRef, 3)
	require.NoError(t, err)

	// Tamper leaf value
	p2 := p
	p2.Value[0] ^= 0xFF
	ok, _, _, err := VerifyInclusion(sha256.New(), rootHash, p2)
	require.ErrorIs(t, err, ErrVerifyInclusionFailed)
	require.False(t, ok)

	// Tamper direction
	p3 := p
	require.NotEmpty(t, p3.Steps)
	p3.Steps[0].Dir ^= 1
	ok, _, _, err = VerifyInclusion(sha256.New(), rootHash, p3)
	require.ErrorIs(t, err, ErrVerifyInclusionFailed)
	require.False(t, ok)
}

func TestVerifyExclusionFailsIfTampered(t *testing.T) {
	keys := []uint64{10, 20, 30, 40}
	leafCount := uint64(len(keys))

	leafTable := make([]byte, LeafTableBytes(leafCount))
	nodeStore := make([]byte, NodeStoreBytes(leafCount))

	b, err := NewBuilder(sha256.New(), leafTable, nodeStore)
	require.NoError(t, err)

	var v [HashBytes]byte
	v[0] = 0x11

	for _, k := range keys {
		_, err := b.InsertMonotone(k, v[:])
		require.NoError(t, err)
	}

	rootRef, rootHash, err := b.Finalize()
	require.NoError(t, err)
	checkNodeStoreInvariants(t, nodeStore, rootRef)

	p, err := ProveExclusion(leafTable, nodeStore, rootRef, 25)
	require.NoError(t, err)

	// Tamper: claim encounteredKey==targetKey.
	p2 := p
	p2.EncounteredKey = p2.TargetKey
	ok, _, _, _, err := VerifyExclusion(sha256.New(), rootHash, p2)
	require.ErrorIs(t, err, ErrVerifyExclusionFailed)
	require.False(t, ok)

	// Tamper: wrong direction bit.
	p3 := p
	require.NotEmpty(t, p3.Steps)
	p3.Steps[0].Dir ^= 1
	ok, _, _, _, err = VerifyExclusion(sha256.New(), rootHash, p3)
	require.ErrorIs(t, err, ErrVerifyExclusionFailed)
	require.False(t, ok)
}

func checkNodeStoreInvariants(t *testing.T, nodeStore []byte, root Ref) {
	t.Helper()
	require.NotEqual(t, NoRef, root)

	used := uint32(root) + 1
	require.LessOrEqual(t, uint64(used)*NodeRecordBytes, uint64(len(nodeStore)))

	for i := uint32(0); i < used; i++ {
		ref := Ref(i)
		k := NodeKindAt(nodeStore, ref)
		require.NotEqualf(t, NodeKind(0), k, "unexpected zero kind at ref=%d (root=%d)", i, root)

		switch k {
		case KindLeaf:
			require.Equalf(t, uint32(0), NodeRightSpan(nodeStore, ref), "leaf rightSpan must be 0 at ref=%d", i)
			require.Equalf(t, uint32(1), NodeSubtreeSize(nodeStore, ref), "leaf subtreeSize must be 1 at ref=%d", i)
		case KindBranch:
			bit := NodeBit(nodeStore, ref)
			require.LessOrEqualf(t, bit, uint8(63), "branch bit out of range at ref=%d", i)

			rs := NodeRightSpan(nodeStore, ref)
			ss := NodeSubtreeSize(nodeStore, ref)
			require.NotZerof(t, rs, "branch rightSpan must be nonzero at ref=%d", i)
			require.Greaterf(t, ss, uint32(1), "branch subtreeSize too small at ref=%d", i)
			require.GreaterOrEqualf(t, ss, rs+2, "branch subtreeSize must be >= rightSpan+2 at ref=%d", i)

			require.Greaterf(t, i, uint32(0), "branch ref must be >0 at ref=%d", i)
			right := Ref(i - 1)
			left := Ref(uint32(i-1) - rs)

			require.Lessf(t, left, right, "invalid left/right ordering at ref=%d", i)

			// In B′ encoding, rightSpan must equal the subtreeSize of rightRoot.
			require.Equalf(t, rs, NodeSubtreeSize(nodeStore, right), "rightSpan != subtreeSize(rightRoot) at ref=%d", i)

			ls := NodeSubtreeSize(nodeStore, left)
			rs2 := NodeSubtreeSize(nodeStore, right)
			require.Equalf(t, ss, ls+rs2+1, "subtreeSize != left+right+1 at ref=%d", i)
		default:
			require.Failf(t, "invalid node kind", "ref=%d kind=%d", i, k)
		}
	}
}

func TestLeafOrdinalToMMRIndex(t *testing.T) {
	// Choose a non-zero first leaf index to ensure offset math is correct.
	firstLeafIndex := uint64(8)
	firstLeafMMRIndex := mmr.MMRIndex(firstLeafIndex)

	for ord := uint64(0); ord < 16; ord++ {
		got := LeafOrdinalToMMRIndex(firstLeafMMRIndex, ord)
		want := mmr.MMRIndex(firstLeafIndex + ord)
		require.Equal(t, want, got)
	}
}
