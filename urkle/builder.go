package urkle

import (
	"hash"
	"math/bits"
)

// Builder performs append-only construction of a postorder (B′) Urkle trie
// over strictly-increasing uint64 keys, writing in-place into preallocated storage.
type Builder struct {
	hasher hash.Hash

	leafTable []byte
	nodeStore []byte

	leafCap uint32
	nodeCap uint32

	st FrontierStateV1
}

func NewBuilder(hasher hash.Hash, leafTable []byte, nodeStore []byte) (*Builder, error) {
	b := &Builder{
		hasher:    hasher,
		leafTable: leafTable,
		nodeStore: nodeStore,
	}
	if err := b.initCaps(); err != nil {
		return nil, err
	}
	b.st.Pending = NoRef
	b.st.Next = 0
	b.st.NextLeaf = 0
	b.st.Depth = 0
	return b, nil
}

func NewBuilderFromFrontier(hasher hash.Hash, leafTable []byte, nodeStore []byte, frontier []byte) (*Builder, error) {
	b := &Builder{
		hasher:    hasher,
		leafTable: leafTable,
		nodeStore: nodeStore,
	}
	if err := b.initCaps(); err != nil {
		return nil, err
	}
	st, ok, err := DecodeFrontierV1(frontier)
	if err != nil {
		return nil, err
	}
	if !ok {
		b.st.Pending = NoRef
		b.st.Next = 0
		b.st.NextLeaf = 0
		b.st.Depth = 0
		return b, nil
	}
	b.st = st
	return b, nil
}

func (b *Builder) initCaps() error {
	if len(b.leafTable)%LeafRecordBytes != 0 {
		return ErrLeafTableBadSize
	}
	leafCap := uint64(len(b.leafTable) / LeafRecordBytes)
	if leafCap > uint64(^uint32(0)) {
		return ErrLeafCountDoesNotFit32
	}
	b.leafCap = uint32(leafCap)

	if len(b.nodeStore)%NodeRecordBytes != 0 {
		return ErrNodeStoreBadSize
	}
	nodeCap := uint64(len(b.nodeStore) / NodeRecordBytes)
	if nodeCap > uint64(^uint32(0)) {
		return ErrNodeStoreBadSize
	}
	b.nodeCap = uint32(nodeCap)

	// Sanity: a maximal trie with leafCap leaves needs <= 2*leafCap-1 nodes.
	want := NodeCountMax(uint64(b.leafCap))
	if want > uint64(b.nodeCap) {
		return ErrNodeStoreBadSize
	}

	return nil
}

// Frontier exports the builder's resumable state.
func (b *Builder) Frontier() FrontierStateV1 {
	return b.st
}

// SaveFrontier encodes the builder state into dst (see FrontierStateV1Bytes).
func (b *Builder) SaveFrontier(dst []byte) error {
	return EncodeFrontierV1(dst, b.st)
}

// InsertMonotone inserts (key,valueBytes) into the trie.
//
// key MUST be strictly increasing across calls.
func (b *Builder) InsertMonotone(key uint64, valueBytes []byte) (leafOrdinal uint32, err error) {
	if len(valueBytes) != HashBytes {
		return 0, ErrBadValueSize
	}
	// Enforce strict ordering (required for append-only emission).
	if b.st.NextLeaf != 0 {
		if key < b.st.LastKey {
			return 0, ErrOutOfOrderKey
		}
		if key == b.st.LastKey {
			return 0, ErrDuplicateKey
		}
	}

	if b.st.NextLeaf >= b.leafCap {
		return 0, ErrInvalidLeafOrdinal
	}
	leafOrdinal = b.st.NextLeaf

	// Persist leaf payload.
	LeafSet(b.leafTable, leafOrdinal, key, valueBytes)

	// Precompute leaf hash; we may delay emitting the leaf node record until
	// after we close any completed frames to preserve B′ postorder contiguity.
	leafHash, err := HashLeaf(b.hasher, key, leafOrdinal, valueBytes)
	if err != nil {
		return 0, err
	}

	// First insert is trivial: pending points at the only subtree.
	if b.st.NextLeaf == 0 {
		leafRef, err := b.emitLeaf(leafOrdinal, leafHash)
		if err != nil {
			return 0, err
		}
		b.st.Pending = leafRef
		b.st.LastKey = key
		b.st.NextLeaf++
		return leafOrdinal, nil
	}

	// Determine the crit-bit against the previous key.
	l, ok := critBit(b.st.LastKey, key)
	if !ok {
		// Should be impossible due to duplicate check above.
		return 0, ErrDuplicateKey
	}

	// Close any frames that are now known complete.
	for b.st.Depth > 0 && b.st.Frames[b.st.Depth-1].Bit > l {
		top := b.st.Frames[b.st.Depth-1]
		b.st.Depth--

		br, err := b.emitBranch(top.Bit, top.Left, b.st.Pending)
		if err != nil {
			return 0, err
		}
		b.st.Pending = br
	}

	// Open a new frame at l if we are descending deeper than current top.
	if b.st.Depth == 0 || b.st.Frames[b.st.Depth-1].Bit < l {
		if b.st.Depth >= FrontierMaxDepth {
			return 0, ErrInvalidBranchBit
		}
		b.st.Frames[b.st.Depth] = Frame{Bit: l, Left: b.st.Pending}
		b.st.Depth++
	}

	// The new key is now the rightmost subtree.
	leafRef, err := b.emitLeaf(leafOrdinal, leafHash)
	if err != nil {
		return 0, err
	}
	b.st.Pending = leafRef
	b.st.LastKey = key
	b.st.NextLeaf++
	return leafOrdinal, nil
}

// Finalize closes any remaining open frames and returns the root ref and hash.
func (b *Builder) Finalize() (Ref, [HashBytes]byte, error) {
	if b.st.NextLeaf == 0 {
		return NoRef, [HashBytes]byte{}, nil
	}

	for b.st.Depth > 0 {
		top := b.st.Frames[b.st.Depth-1]
		b.st.Depth--

		br, err := b.emitBranch(top.Bit, top.Left, b.st.Pending)
		if err != nil {
			return NoRef, [HashBytes]byte{}, err
		}
		b.st.Pending = br
	}

	root := b.st.Pending
	return root, NodeHash(b.nodeStore, root), nil
}

func (b *Builder) emitLeaf(leafOrdinal uint32, leafHash [HashBytes]byte) (Ref, error) {
	if uint32(b.st.Next) >= b.nodeCap {
		return 0, ErrNodeStoreBadSize
	}
	ref := b.st.Next
	NodeWriteLeaf(b.nodeStore, ref, leafOrdinal, leafHash)
	b.st.Next++
	return ref, nil
}

func (b *Builder) emitBranch(bit uint8, leftRef Ref, rightRef Ref) (Ref, error) {
	if uint32(b.st.Next) >= b.nodeCap {
		return 0, ErrNodeStoreBadSize
	}
	if bit > 63 {
		return 0, ErrInvalidBranchBit
	}

	leftSize := NodeSubtreeSize(b.nodeStore, leftRef)
	rightSize := NodeSubtreeSize(b.nodeStore, rightRef)
	if leftSize == 0 || rightSize == 0 {
		return 0, ErrInvalidSubtreeSize
	}

	subtreeSize64 := uint64(leftSize) + uint64(rightSize) + 1
	if subtreeSize64 > uint64(^uint32(0)) {
		return 0, ErrInvalidSubtreeSize
	}
	subtreeSize := uint32(subtreeSize64)

	leftHash := NodeHash(b.nodeStore, leftRef)
	rightHash := NodeHash(b.nodeStore, rightRef)
	brHash, err := HashBranch(b.hasher, bit, leftHash, rightHash)
	if err != nil {
		return 0, err
	}

	ref := b.st.Next
	NodeWriteBranch(b.nodeStore, ref, bit, rightSize, subtreeSize, brHash)
	b.st.Next++
	return ref, nil
}

// critBit returns the first differing MSB-first bit index between a and b.
// ok=false indicates a==b.
func critBit(a, b uint64) (idx uint8, ok bool) {
	x := a ^ b
	if x == 0 {
		return 0, false
	}
	return uint8(bits.LeadingZeros64(x)), true
}
