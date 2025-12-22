package urkle

import (
	"bytes"
	"fmt"
	"hash"
)

type ProofStep struct {
	Bit         uint8
	Dir         uint8 // 0=went left, 1=went right
	SiblingHash [HashBytes]byte
}

// InclusionProof proves that Key is present and yields (LeafOrdinal, Value).
// Steps are ordered from leaf -> root.
type InclusionProof struct {
	Key        uint64
	LeafOrdinal uint32
	Value      [HashBytes]byte
	Steps      []ProofStep
}

// ExclusionProof proves that TargetKey is absent by returning the membership proof
// for the encountered leaf reached by traversing with TargetKey.
//
// Steps are ordered from leaf -> root.
type ExclusionProof struct {
	TargetKey     uint64
	EncounteredKey uint64
	LeafOrdinal   uint32
	Value         [HashBytes]byte
	Steps         []ProofStep
}

// ProveInclusion generates an inclusion proof for key under the trie rooted at root.
func ProveInclusion(leafTable, nodeStore []byte, root Ref, key uint64) (InclusionProof, error) {
	if root == NoRef {
		return InclusionProof{}, ErrEmptyTrie
	}

	leafRef, stepsRT, err := provePath(nodeStore, root, key)
	if err != nil {
		return InclusionProof{}, err
	}

	leafOrdinal := NodeLeafOrdinal(nodeStore, leafRef)
	encKey := LeafKey(leafTable, leafOrdinal)
	if encKey != key {
		return InclusionProof{}, ErrKeyNotFound
	}
	val := LeafValue(leafTable, leafOrdinal)

	steps := reverseSteps(stepsRT)
	return InclusionProof{
		Key:         key,
		LeafOrdinal: leafOrdinal,
		Value:       val,
		Steps:       steps,
	}, nil
}

// ProveExclusion generates an exclusion proof for targetKey under the trie rooted at root.
func ProveExclusion(leafTable, nodeStore []byte, root Ref, targetKey uint64) (ExclusionProof, error) {
	if root == NoRef {
		return ExclusionProof{}, ErrEmptyTrie
	}

	leafRef, stepsRT, err := provePath(nodeStore, root, targetKey)
	if err != nil {
		return ExclusionProof{}, err
	}

	leafOrdinal := NodeLeafOrdinal(nodeStore, leafRef)
	encKey := LeafKey(leafTable, leafOrdinal)
	if encKey == targetKey {
		return ExclusionProof{}, ErrKeyPresent
	}
	val := LeafValue(leafTable, leafOrdinal)

	steps := reverseSteps(stepsRT)
	return ExclusionProof{
		TargetKey:      targetKey,
		EncounteredKey: encKey,
		LeafOrdinal:    leafOrdinal,
		Value:          val,
		Steps:          steps,
	}, nil
}

// VerifyInclusion verifies an inclusion proof against expectedRoot.
//
// On success, returns (true, leafOrdinal, valueBytes, nil).
func VerifyInclusion(hasher hash.Hash, expectedRoot [HashBytes]byte, p InclusionProof) (bool, uint32, [HashBytes]byte, error) {
	leafHash, err := HashLeaf(hasher, p.Key, p.LeafOrdinal, p.Value[:])
	if err != nil {
		return false, 0, [HashBytes]byte{}, err
	}

	cur := leafHash
	for _, s := range p.Steps {
		if s.Dir != bitAt(p.Key, s.Bit) {
			return false, 0, [HashBytes]byte{}, fmt.Errorf("%w: path dir mismatch", ErrVerifyInclusionFailed)
		}

		var left, right [HashBytes]byte
		if s.Dir == 0 {
			left, right = cur, s.SiblingHash
		} else {
			left, right = s.SiblingHash, cur
		}

		cur, err = HashBranch(hasher, s.Bit, left, right)
		if err != nil {
			return false, 0, [HashBytes]byte{}, err
		}
	}

	if !bytes.Equal(cur[:], expectedRoot[:]) {
		return false, 0, [HashBytes]byte{}, ErrVerifyInclusionFailed
	}
	return true, p.LeafOrdinal, p.Value, nil
}

// VerifyExclusion verifies an exclusion proof against expectedRoot.
//
// On success, returns (true, encounteredKey, leafOrdinal, valueBytes, nil).
func VerifyExclusion(hasher hash.Hash, expectedRoot [HashBytes]byte, p ExclusionProof) (bool, uint64, uint32, [HashBytes]byte, error) {
	if p.EncounteredKey == p.TargetKey {
		return false, 0, 0, [HashBytes]byte{}, ErrVerifyExclusionFailed
	}

	leafHash, err := HashLeaf(hasher, p.EncounteredKey, p.LeafOrdinal, p.Value[:])
	if err != nil {
		return false, 0, 0, [HashBytes]byte{}, err
	}

	cur := leafHash
	for _, s := range p.Steps {
		// For exclusion, we must ensure the proof path is the search path for TargetKey.
		if s.Dir != bitAt(p.TargetKey, s.Bit) {
			return false, 0, 0, [HashBytes]byte{}, fmt.Errorf("%w: path dir mismatch", ErrVerifyExclusionFailed)
		}

		var left, right [HashBytes]byte
		if s.Dir == 0 {
			left, right = cur, s.SiblingHash
		} else {
			left, right = s.SiblingHash, cur
		}

		cur, err = HashBranch(hasher, s.Bit, left, right)
		if err != nil {
			return false, 0, 0, [HashBytes]byte{}, err
		}
	}

	if !bytes.Equal(cur[:], expectedRoot[:]) {
		return false, 0, 0, [HashBytes]byte{}, ErrVerifyExclusionFailed
	}

	return true, p.EncounteredKey, p.LeafOrdinal, p.Value, nil
}

// provePath traverses from root to a leaf using targetKey bits and returns:
//   - the encountered leaf ref
//   - steps ordered root -> leaf
func provePath(nodeStore []byte, root Ref, targetKey uint64) (Ref, []ProofStep, error) {
	cur := root
	var steps []ProofStep

	for {
		switch NodeKindAt(nodeStore, cur) {
		case KindLeaf:
			return cur, steps, nil
		case KindBranch:
			bit := NodeBit(nodeStore, cur)
			if bit > 63 {
				return 0, nil, ErrInvalidBranchBit
			}

			rs := NodeRightSpan(nodeStore, cur)
			if rs == 0 {
				return 0, nil, ErrInvalidRightSpan
			}

			if cur == 0 {
				return 0, nil, ErrInvalidRightSpan
			}

			right := cur - 1
			left64 := uint64(cur) - 1 - uint64(rs)
			if left64 > uint64(right) {
				return 0, nil, ErrInvalidRightSpan
			}
			left := Ref(left64)

			dir := bitAt(targetKey, bit)

			var next, sib Ref
			if dir == 0 {
				next, sib = left, right
			} else {
				next, sib = right, left
			}

			steps = append(steps, ProofStep{
				Bit:         bit,
				Dir:         dir,
				SiblingHash: NodeHash(nodeStore, sib),
			})

			cur = next
		default:
			return 0, nil, ErrInvalidNodeKind
		}
	}
}

func reverseSteps(in []ProofStep) []ProofStep {
	out := make([]ProofStep, len(in))
	copy(out, in)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}


