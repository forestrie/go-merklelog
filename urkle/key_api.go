package urkle

import (
	"errors"
	"fmt"
)

var (
	// ErrLeafOrdinalDoesNotFit16 indicates a found leafOrdinal cannot be represented as uint16.
	ErrLeafOrdinalDoesNotFit16 = errors.New("urkle: leaf ordinal does not fit in uint16")
)

// ProveInclusionFromView generates an inclusion proof for key under the trie rooted at root.
func ProveInclusionFromView(v IndexView, root Ref, key uint64) (InclusionProof, error) {
	return ProveInclusion(v.LeafTable, v.NodeStore, root, key)
}

// ProveExclusionFromView generates an exclusion proof for targetKey under the trie rooted at root.
func ProveExclusionFromView(v IndexView, root Ref, targetKey uint64) (ExclusionProof, error) {
	return ProveExclusion(v.LeafTable, v.NodeStore, root, targetKey)
}

// KeyLeafOrdinal returns the leafOrdinal for idtimestamp if it is present in the trie.
//
// Returns ErrKeyNotFound if the key is absent.
func KeyLeafOrdinal(v IndexView, root Ref, idtimestamp uint64) (uint16, error) {
	ord32, err := keyLeafOrdinal(v, root, idtimestamp)
	if err != nil {
		return 0, err
	}
	if ord32 > uint32(^uint16(0)) {
		return 0, ErrLeafOrdinalDoesNotFit16
	}
	return uint16(ord32), nil
}

// KeyMMRIndex returns the MMR index for idtimestamp if it is present in the trie.
//
// firstLeafMMRIndex is the MMR index of the first leaf in the chunk (from massif start context).
func KeyMMRIndex(v IndexView, root Ref, idtimestamp uint64, firstLeafMMRIndex uint64) (uint64, error) {
	ord, err := KeyLeafOrdinal(v, root, idtimestamp)
	if err != nil {
		return 0, err
	}
	return LeafOrdinalToMMRIndex(firstLeafMMRIndex, uint64(ord)), nil
}

func keyLeafOrdinal(v IndexView, root Ref, idtimestamp uint64) (uint32, error) {
	if root == NoRef {
		return 0, ErrEmptyTrie
	}

	leafRef, err := findLeafRef(v.NodeStore, root, idtimestamp)
	if err != nil {
		return 0, err
	}

	leafOrdinal := NodeLeafOrdinal(v.NodeStore, leafRef)
	if leafOrdinal >= uint32(v.LeafCount) {
		return 0, ErrInvalidLeafOrdinal
	}
	encKey := LeafKey(v.LeafTable, leafOrdinal)
	if encKey != idtimestamp {
		return 0, ErrKeyNotFound
	}
	return leafOrdinal, nil
}

// findLeafRef traverses from root to a leaf using targetKey bits and returns the encountered leaf ref.
//
// This mirrors provePath but avoids allocating proof steps.
func findLeafRef(nodeStore []byte, root Ref, targetKey uint64) (Ref, error) {
	cur := root
	for {
		switch NodeKindAt(nodeStore, cur) {
		case KindLeaf:
			return cur, nil
		case KindBranch:
			bit := NodeBit(nodeStore, cur)
			if bit > 63 {
				return 0, ErrInvalidBranchBit
			}

			rs := NodeRightSpan(nodeStore, cur)
			if rs == 0 {
				return 0, ErrInvalidRightSpan
			}
			if cur == 0 {
				return 0, ErrInvalidRightSpan
			}

			right := cur - 1
			left64 := uint64(cur) - 1 - uint64(rs)
			if left64 > uint64(right) {
				return 0, ErrInvalidRightSpan
			}
			left := Ref(left64)

			dir := bitAt(targetKey, bit)
			if dir == 0 {
				cur = left
			} else {
				cur = right
			}
		default:
			return 0, fmt.Errorf("%w: ref=%d", ErrInvalidNodeKind, cur)
		}
	}
}
