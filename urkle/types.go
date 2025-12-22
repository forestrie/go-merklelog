package urkle

import "errors"

// HashBytes is the fixed width of hashes and values used by Forestrie index structures.
// This matches `massifs.ValueBytes`.
const HashBytes = 32

// LeafOrdinalBytes is the byte width used to encode leafOrdinal in proofs and leaf hashes.
const LeafOrdinalBytes = 4

// LeafRecordBytes is the fixed byte width of a leaf table record.
//
// v1 layout (extended for Forestrie v2 index needs):
//   - key_be8 (uint64)
//   - valueBytes[32]
//   - extra1[24] (auxiliary; not committed by the trie hash)
//   - extra2[32] (auxiliary; not committed by the trie hash)
//   - extra3[32] (auxiliary; not committed by the trie hash)
//
// NOTE: The record size is intentionally a multiple of 32 bytes. To achieve this
// without truncating valueBytes (which is committed by the trie hash), we
// sacrifice 8 bytes from the first extra field.
const LeafRecordBytes = 8 + HashBytes + (HashBytes - 8) + 2*HashBytes // 128

// NodeRecordBytes is the fixed byte width of a node store record.
// See `noderecord.go` for the field layout.
const NodeRecordBytes = 64

// Ref is a node-store record index.
type Ref uint32

const NoRef = ^Ref(0)

type NodeKind uint8

const (
	KindLeaf   NodeKind = 1
	KindBranch NodeKind = 2
)

var (
	ErrBadHashSize           = errors.New("urkle: hasher output must be 32 bytes")
	ErrBadValueSize          = errors.New("urkle: valueBytes must be 32 bytes")
	ErrLeafTableBadSize      = errors.New("urkle: leaf table buffer size invalid")
	ErrNodeStoreBadSize      = errors.New("urkle: node store buffer size invalid")
	ErrFrontierBadSize       = errors.New("urkle: frontier buffer size invalid")
	ErrFrontierBadMagic      = errors.New("urkle: frontier magic invalid")
	ErrFrontierBadVersion    = errors.New("urkle: frontier version invalid")
	ErrOutOfOrderKey         = errors.New("urkle: key out of order")
	ErrDuplicateKey          = errors.New("urkle: duplicate key")
	ErrInvalidNodeKind       = errors.New("urkle: invalid node kind")
	ErrInvalidBranchBit      = errors.New("urkle: invalid branch bit")
	ErrInvalidSubtreeSize    = errors.New("urkle: invalid subtree size")
	ErrInvalidRightSpan      = errors.New("urkle: invalid right span")
	ErrInvalidLeafOrdinal    = errors.New("urkle: invalid leaf ordinal")
	ErrLeafCountDoesNotFit32 = errors.New("urkle: leafCount does not fit in uint32")
	ErrLeafOrdinalDoesNotFit = errors.New("urkle: leafOrdinal does not fit the configured width")

	ErrEmptyTrie             = errors.New("urkle: empty trie")
	ErrKeyNotFound           = errors.New("urkle: key not found")
	ErrKeyPresent            = errors.New("urkle: key present")
	ErrVerifyInclusionFailed = errors.New("urkle: verify inclusion failed")
	ErrVerifyExclusionFailed = errors.New("urkle: verify exclusion failed")
)
