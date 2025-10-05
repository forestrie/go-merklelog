package mmr

import (
	"bytes"
	"hash"
)

// Verification is by default against the MRR accumulator peaks (see verify.go). The "Bagged"
// variants work with proofs against a "Bagged" singular mono root for an MMR.
// We may remove these methods in future.

// VerifyInclusionBagged returns true if the provided proof demonstrates inclusion of
// nodeHash at position iLeaf+1
//
// proof and root should be obtained via InclusionProof and GetRoot respectively.
//
// Remembering that the proof layout is this:
//
//	[local-peak-proof-i, right-sibling-of-i, left-of-i-peaks-reversed]
//
// And given the following MMR
//
//	3            15
//	           /    \
//	          /      \
//	         /        \
//	2       7          14             22
//	      /   \       /   \          /   \
//	1    3     6    10     13      18      21      25
//	    / \  /  \   / \   /  \    /  \    /  \    /   \
//	0  1   2 4   5 8   9 11   12 16   17 19   20 23   24 26
//
// Note that only the local-peak-proof-i elements will include the commitment to
// the number of descendent tree nodes. This means we must include H(pos) for
// each step in local-peak-proof-i, but then exclude it in all the others.
//
// So if we have a proof for leaf position 17 (iLeaf=16) the proof will be
// composed of the local peak proof for 17, which is
//
//	[ValueAt(16), ValueAt(21), Bagged-Peaks-RHS, Reveresed-LHS-Peaks]
//
// To correctly account for the position in the proof, we need to pre-pend the
// position for each element in the local peak proof:
//
// H(22 | V(21) | H(18|leaf|V(16)))
//
// Remembering that, confusingly, we always include the value for the 'right'
// node first despite the fact that reading order makes this seem 'on the left'
func VerifyInclusionBagged(
	mmrSize uint64, hasher hash.Hash, nodeHash []byte, iNode uint64, proof [][]byte, root []byte,
) bool {
	ok, proofLen := VerifyFirstInclusionPathBagged(mmrSize, hasher, nodeHash, iNode, proof, root)
	return ok && proofLen == len(proof)
}

// VerifyFirstInclusionPathBagged process the proof until it re-produces the "bagged" root of the MMR
//
// This method exists for the situation where multiple, possibly related, proofs
// are catenated together in the same path. As they are in log consistency
// proofs, when they are proven against a mono root.
// See [forstrie/go-merklelog/mmr/VerifyInclusion] for further details.
//
// Returns
//
//	true and the length of the verified path in proof on success.
//	false if it reaches the end of proof.
func VerifyFirstInclusionPathBagged(
	mmrSize uint64, hasher hash.Hash, leafHash []byte, iNode uint64, proof [][]byte, root []byte,
) (bool, int) {

	peaks := PosPeaks(mmrSize)
	peakMap := map[uint64]bool{}

	// Deal with the degenerate case where iNode is a perfect peak. The proof will be nil.
	if len(proof) == 0 && bytes.Equal(leafHash, root) {
		return true, 0
	}

	heightIndex := IndexHeight(iNode) // allows for proofs of interior nodes
	pos := iNode + 1
	elementHash := leafHash

	// The peaks are listed smallest to highest, and the proof starts with the
	// local peak proof, so the first peak larger than iLeaf+1 can safely be
	// used to spot the completion of the local peak proof.
	var localPeak uint64
	for _, peakPos := range peaks {
		// Note the position of the local peak, so we can spot when the local proof is complete
		if localPeak == 0 && peakPos >= pos {
			localPeak = peakPos
		}
		peakMap[peakPos] = true
	}

	for iProof, p := range proof {

		hasher.Reset()

		// This first clause deals with accumulating the peak hashes. The first
		// time it hits will be the peak for the local tree containing iLeaf.
		// There are 3 cases:
		//  a) The mmr size is 1, and so iLeaf = pos -1
		//  b) The mmr has a size that leaves a singleton at the lowest end of the MMR range.
		//  c) The normal local peak case
		//
		// Both a) and b) would be dealt with on the first pass, c) is triggered
		// after we have traversed and accumulated the leaf proof for the local
		// tree
		if _, ok := peakMap[pos]; ok {

			if pos == peaks[len(peaks)-1] {

				// case a) or c)
				hasher.Write(elementHash)
				hasher.Write(p)
			} else {
				// case b) or c)
				hasher.Write(p)
				hasher.Write(elementHash)
				pos = peaks[len(peaks)-1]
			}
			elementHash = hasher.Sum(nil)
			if bytes.Equal(elementHash, root) {
				// If we have the root then we have successfully completed the
				// current proof.  Return the index for the start of the next
				return true, iProof + 1
			}

			continue
		}

		// verify the merkle path
		nextHeight := PosHeight(pos + 1)

		if nextHeight > heightIndex {
			// we are at the right child

			// Advance pos first, so we can use the parent pos to decide wether
			// we are still processing the local peak proof.
			pos += 1
			if pos <= localPeak {
				HashWriteUint64(hasher, pos) // pos is now the parent pos, which was also the commit value
			}
			hasher.Write(p)
			hasher.Write(elementHash)
		} else {
			// we are at the left child

			// Advance pos first, so we can use the parent pos to decide wether
			// we are still processing the local peak proof.
			pos += 2 << heightIndex
			if pos <= localPeak {
				HashWriteUint64(hasher, pos) // pos is now the parent pos, which was also the commit value
			}
			hasher.Write(elementHash)
			hasher.Write(p)

		}

		elementHash = hasher.Sum(nil)

		if bytes.Equal(elementHash, root) {
			// If we have the root then we have successfully completed the
			// current proof.  Return the index for the start of the next
			return true, iProof + 1
		}

		heightIndex += 1
	}
	return false, len(proof)
}
