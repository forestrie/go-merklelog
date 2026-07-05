package urkle

import (
	"crypto/sha256"
	"errors"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeFrontierV1_RoundTrip(t *testing.T) {
	var st FrontierStateV1
	st.LastKey = 0x0102030405060708
	st.Pending = 5
	st.Next = 10
	st.NextLeaf = 7
	st.Depth = 2
	st.Frames[0] = Frame{Bit: 3, Left: 1}
	st.Frames[1] = Frame{Bit: 10, Left: 4}

	dst := make([]byte, FrontierStateV1Bytes)
	require.NoError(t, EncodeFrontierV1(dst, st))

	got, ok, err := DecodeFrontierV1(dst)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, st.LastKey, got.LastKey)
	require.Equal(t, st.Pending, got.Pending)
	require.Equal(t, st.Next, got.Next)
	require.Equal(t, st.NextLeaf, got.NextLeaf)
	require.Equal(t, st.Depth, got.Depth)
	require.Equal(t, st.Frames[0], got.Frames[0])
	require.Equal(t, st.Frames[1], got.Frames[1])
}

func TestDecodeFrontierV1_EmptyZeroBlock(t *testing.T) {
	src := make([]byte, FrontierStateV1Bytes)

	st, ok, err := DecodeFrontierV1(src)
	require.NoError(t, err)
	require.False(t, ok)
	require.Equal(t, FrontierStateV1{}, st)
}

func TestDecodeFrontierV1_TruncatedBuffer(t *testing.T) {
	src := make([]byte, FrontierStateV1Bytes-1)

	_, ok, err := DecodeFrontierV1(src)
	require.ErrorIs(t, err, ErrFrontierBadSize)
	require.False(t, ok)
}

func TestDecodeFrontierV1_BadMagicAndVersion(t *testing.T) {
	// Start from a valid encoding.
	var st FrontierStateV1
	st.LastKey = 1
	dst := make([]byte, FrontierStateV1Bytes)
	require.NoError(t, EncodeFrontierV1(dst, st))

	// Bad magic.
	dstBadMagic := append([]byte{}, dst...)
	dstBadMagic[0] = 'X'
	_, ok, err := DecodeFrontierV1(dstBadMagic)
	require.ErrorIs(t, err, ErrFrontierBadMagic)
	require.False(t, ok)

	// Bad version.
	dstBadVersion := append([]byte{}, dst...)
	dstBadVersion[4] = FrontierVersionV1 + 1
	_, ok, err = DecodeFrontierV1(dstBadVersion)
	require.ErrorIs(t, err, ErrFrontierBadVersion)
	require.False(t, ok)
}

func TestDecodeFrontierV1_InvalidDepthOrPending(t *testing.T) {
	var st FrontierStateV1
	st.LastKey = 1
	st.Pending = NoRef
	st.Depth = 1
	dst := make([]byte, FrontierStateV1Bytes)
	require.NoError(t, EncodeFrontierV1(dst, st))

	_, ok, err := DecodeFrontierV1(dst)
	require.ErrorIs(t, err, ErrFrontierBadState)
	require.False(t, ok)

	// Depth beyond FrontierMaxDepth.
	// Start from a valid encoding and then bump the depth byte.
	st2 := FrontierStateV1{LastKey: 2, Pending: 1, Next: 2, Depth: 0}
	require.NoError(t, EncodeFrontierV1(dst, st2))
	dst[24] = FrontierMaxDepth + 1
	_, ok, err = DecodeFrontierV1(dst)
	require.ErrorIs(t, err, ErrFrontierBadState)
	require.False(t, ok)
}

func TestNewBuilderFromFrontier_InvalidStateIsRejected(t *testing.T) {
	leafTable := make([]byte, LeafTableBytes(4))
	nodeStore := make([]byte, NodeStoreBytes(4))

	// Construct a frontier with impossible NextLeaf > leafCap.
	st := FrontierStateV1{
		LastKey:  1,
		Pending:  0,
		Next:     0,
		NextLeaf: ^uint32(0),
		Depth:    0,
	}
	frontier := make([]byte, FrontierStateV1Bytes)
	require.NoError(t, EncodeFrontierV1(frontier, st))

	b, err := NewBuilderFromFrontier(newNopHasher(), leafTable, nodeStore, frontier)
	require.Nil(t, b)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrFrontierBadState))
}

func TestNewBuilderFromFrontier_InvalidPendingIsRejected(t *testing.T) {
	// leafCap=4 -> nodeCap=NodeCountMax(4)=7. A Pending of nodeCap is outside
	// the node store slice; without validation it would panic in emitBranch /
	// Finalize when the ref is dereferenced, rather than being rejected here.
	leafTable := make([]byte, LeafTableBytes(4))
	nodeStore := make([]byte, NodeStoreBytes(4))
	nodeCap := uint32(len(nodeStore) / NodeRecordBytes)

	cases := []struct {
		name string
		st   FrontierStateV1
	}{
		{
			// Depth=0: Finalize would take root := Pending and read
			// NodeHash(nodeStore, Pending) out of bounds.
			name: "pending out of bounds, depth 0",
			st: FrontierStateV1{
				LastKey:  1,
				Pending:  Ref(nodeCap),
				Next:     1,
				NextLeaf: 1,
				Depth:    0,
			},
		},
		{
			// Pending == NoRef with a non-empty trie is likewise invalid; the
			// InsertMonotone-then-close path would smuggle it into a frame Left.
			name: "pending noref, non-empty trie",
			st: FrontierStateV1{
				LastKey:  1,
				Pending:  NoRef,
				Next:     1,
				NextLeaf: 1,
				Depth:    0,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			frontier := make([]byte, FrontierStateV1Bytes)
			require.NoError(t, EncodeFrontierV1(frontier, tc.st))

			// Must return a clean error, never panic.
			b, err := NewBuilderFromFrontier(newNopHasher(), leafTable, nodeStore, frontier)
			require.Nil(t, b)
			require.ErrorIs(t, err, ErrFrontierBadState)
		})
	}
}

// nopHasher is a minimal hash.Hash implementation used only for tests.
// It delegates to SHA-256 but ignores Sum's argument and always returns
// a 32-byte digest, as required by the urkle package.
type nopHasher struct {
	h hash.Hash
}

func newNopHasher() hash.Hash {
	return &nopHasher{h: sha256.New()}
}

func (n *nopHasher) Write(p []byte) (int, error) { return n.h.Write(p) }
func (n *nopHasher) Sum(b []byte) []byte         { return n.h.Sum(b[:0]) }
func (n *nopHasher) Reset()                      { n.h.Reset() }
func (n *nopHasher) Size() int                   { return n.h.Size() }
func (n *nopHasher) BlockSize() int              { return n.h.BlockSize() }
