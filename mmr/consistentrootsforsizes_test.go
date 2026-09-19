package mmr

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ConsistentRootsForSizes: the proof shape is fixed by the two sizes.
//
// The tests below mirror the reference suites for the same algorithm (the
// python tests over the draft's canonical 39 node MMR and the solidity KAT and
// shape tests), so the three implementations accept and reject the same
// material.

// consistentRootsPair returns the proof paths and the two accumulators for the
// complete mmr indices ifrom and ito, read from the canonical KAT-39 db. The
// paths are exactly the shape the two sizes imply.
func consistentRootsPair(
	t *testing.T, db *testDb, ifrom, ito uint64,
) ([][][]byte, [][]byte, [][]byte) {
	cp, err := IndexConsistencyProof(db, ifrom, ito)
	require.NoError(t, err)
	accFrom, err := PeakHashes(db, ifrom)
	require.NoError(t, err)
	accTo, err := PeakHashes(db, ito)
	require.NoError(t, err)
	return cp.Path, accFrom, accTo
}

// copyProofPaths returns a copy the caller can alter without disturbing the
// original paths.
func copyProofPaths(proofs [][][]byte) [][][]byte {
	copied := make([][][]byte, len(proofs))
	for i, path := range proofs {
		copied[i] = make([][]byte, len(path))
		copy(copied[i], path)
	}
	return copied
}

// replacementHash is a well formed hash value which is not the value the tree
// holds at the position it is substituted for.
func replacementHash(b byte) []byte {
	value := make([]byte, 32)
	for i := range value {
		value[i] = b
	}
	return value
}

// TestConsistentRootsForSizesMatchesConsistentRoots checks, for every ordered
// pair of complete sizes in the canonical 39 node MMR, that the proven roots
// are those ConsistentRoots produces, that they are the leading entries of the
// target accumulator, and that the right peak count accounts for the rest.
func TestConsistentRootsForSizesMatchesConsistentRoots(t *testing.T) {
	db := NewCanonicalTestDB(t)
	hasher := sha256.New()

	pairs := 0
	for i, ito := range KAT39CompleteMMRIndices {
		for _, ifrom := range KAT39CompleteMMRIndices[:i] {
			proofs, accFrom, accTo := consistentRootsPair(t, db, ifrom, ito)

			roots, expectedRight, err := ConsistentRootsForSizes(
				hasher, ifrom+1, ito+1, accFrom, proofs)
			require.NoError(t, err, "sizes %d -> %d", ifrom+1, ito+1)

			want, err := ConsistentRoots(hasher, ifrom, accFrom, proofs)
			require.NoError(t, err)
			assert.Equal(t, want, roots, "sizes %d -> %d", ifrom+1, ito+1)
			assert.Equal(t, accTo[:len(roots)], roots,
				"sizes %d -> %d", ifrom+1, ito+1)
			assert.Equal(t, len(accTo)-len(roots), expectedRight,
				"sizes %d -> %d", ifrom+1, ito+1)
			pairs++
		}
	}
	assert.Equal(t, 210, pairs)
}

// TestConsistentRootsForSizesFromEmptyOrigin checks that from size 0 nothing is
// proven and every target peak is a right peak.
func TestConsistentRootsForSizesFromEmptyOrigin(t *testing.T) {
	db := NewCanonicalTestDB(t)
	hasher := sha256.New()

	for _, ito := range KAT39CompleteMMRIndices {
		roots, expectedRight, err := ConsistentRootsForSizes(
			hasher, 0, ito+1, nil, nil)
		require.NoError(t, err, "size 0 -> %d", ito+1)
		assert.Empty(t, roots)
		accTo, err := PeakHashes(db, ito)
		require.NoError(t, err)
		assert.Equal(t, len(accTo), expectedRight, "size 0 -> %d", ito+1)
	}
}

// TestConsistentRootsForSizesRejectsNonGrowingSizes checks that a target size
// which does not exceed the origin size is rejected: there is no growth to
// prove and the split bit is not defined.
func TestConsistentRootsForSizesRejectsNonGrowingSizes(t *testing.T) {
	db := NewCanonicalTestDB(t)
	hasher := sha256.New()

	accFrom := [][]byte{db.mustGet(2)}
	proofs := [][][]byte{{}}

	for _, sizeTo := range []uint64{3, 1} {
		_, _, err := ConsistentRootsForSizes(hasher, 3, sizeTo, accFrom, proofs)
		require.ErrorIs(t, err, ErrSizesNotIncreasing, "size 3 -> %d", sizeTo)
	}
}

// TestConsistentRootsForSizesRejectsIncompleteTargetSize checks that a target
// size which is no MMR's node count is rejected. PeaksBitmap rounds such a size
// down, so without the check the accumulator would be anchored at a size whose
// entry heights do not match the bitmap.
func TestConsistentRootsForSizesRejectsIncompleteTargetSize(t *testing.T) {
	db := NewCanonicalTestDB(t)
	hasher := sha256.New()

	accFrom := [][]byte{db.mustGet(0)}
	proofs := [][][]byte{{db.mustGet(1)}}

	for _, sizeTo := range []uint64{2, 5, 6, 9} {
		_, _, err := ConsistentRootsForSizes(hasher, 1, sizeTo, accFrom, proofs)
		require.ErrorIs(t, err, ErrIncompleteTreeSize, "size 1 -> %d", sizeTo)
	}
}

// TestConsistentRootsForSizesRejectsEmptyPathWhereSizesImplyOne checks that a
// path of length 0 where the sizes imply a longer path is rejected, so an
// origin peak cannot be re-anchored unchanged at a larger size.
func TestConsistentRootsForSizesRejectsEmptyPathWhereSizesImplyOne(t *testing.T) {
	db := NewCanonicalTestDB(t)
	hasher := sha256.New()

	accFrom := [][]byte{db.mustGet(0)}
	proofs := [][][]byte{{}}

	for _, sizeTo := range []uint64{3, 7} {
		_, _, err := ConsistentRootsForSizes(hasher, 1, sizeTo, accFrom, proofs)
		require.ErrorIs(t, err, ErrConsistencyPathLength, "size 1 -> %d", sizeTo)
	}
}

// TestConsistentRootsForSizesRejectsLengthenedPath checks that adding one
// element to any single path is rejected for every complete pair: the length of
// each path is fixed by the two sizes.
func TestConsistentRootsForSizesRejectsLengthenedPath(t *testing.T) {
	db := NewCanonicalTestDB(t)
	hasher := sha256.New()

	cases := 0
	for i, ito := range KAT39CompleteMMRIndices {
		for _, ifrom := range KAT39CompleteMMRIndices[:i] {
			proofs, accFrom, _ := consistentRootsPair(t, db, ifrom, ito)
			for which := range proofs {
				altered := copyProofPaths(proofs)
				altered[which] = append(altered[which], replacementHash(0x00))
				_, _, err := ConsistentRootsForSizes(
					hasher, ifrom+1, ito+1, accFrom, altered)
				require.ErrorIs(t, err, ErrConsistencyPathLength,
					"sizes %d -> %d, path %d", ifrom+1, ito+1, which)
				cases++
			}
		}
	}
	assert.Equal(t, 399, cases)
}

// TestConsistentRootsForSizesRejectsShortenedPath checks that removing one
// element from any non-empty path is rejected for every complete pair.
func TestConsistentRootsForSizesRejectsShortenedPath(t *testing.T) {
	db := NewCanonicalTestDB(t)
	hasher := sha256.New()

	cases := 0
	for i, ito := range KAT39CompleteMMRIndices {
		for _, ifrom := range KAT39CompleteMMRIndices[:i] {
			proofs, accFrom, _ := consistentRootsPair(t, db, ifrom, ito)
			for which, path := range proofs {
				if len(path) == 0 {
					continue
				}
				altered := copyProofPaths(proofs)
				altered[which] = altered[which][:len(path)-1]
				_, _, err := ConsistentRootsForSizes(
					hasher, ifrom+1, ito+1, accFrom, altered)
				require.ErrorIs(t, err, ErrConsistencyPathLength,
					"sizes %d -> %d, path %d", ifrom+1, ito+1, which)
				cases++
			}
		}
	}
	assert.Equal(t, 338, cases)
}

// TestConsistentRootsForSizesRejectsReplacedSiblingUnderSharedPeak checks that
// when the sizes place two origin peaks under one target peak, replacing the
// first element of the lower path is rejected: the paths no longer agree on the
// root, and a single target peak cannot have two values.
func TestConsistentRootsForSizesRejectsReplacedSiblingUnderSharedPeak(t *testing.T) {
	db := NewCanonicalTestDB(t)
	hasher := sha256.New()

	cases := 0
	for i, ito := range KAT39CompleteMMRIndices {
		for _, ifrom := range KAT39CompleteMMRIndices[:i] {
			proofs, accFrom, _ := consistentRootsPair(t, db, ifrom, ito)
			// The two lowest origin peaks share a target peak exactly when the
			// second lowest is below the split, which its non-empty path shows.
			if len(proofs) < 2 || len(proofs[len(proofs)-2]) == 0 {
				continue
			}
			altered := copyProofPaths(proofs)
			last := len(altered) - 1
			require.NotEmpty(t, altered[last])
			require.False(t, bytes.Equal(altered[last][0], replacementHash(0xff)))
			altered[last][0] = replacementHash(0xff)

			_, _, err := ConsistentRootsForSizes(
				hasher, ifrom+1, ito+1, accFrom, altered)
			require.ErrorIs(t, err, ErrConsistencyRootMismatch,
				"sizes %d -> %d", ifrom+1, ito+1)
			cases++
		}
	}
	assert.Equal(t, 108, cases)
}

// TestConsistentRootsForSizesRejectsPeakCountMismatch checks that an
// accumulator or proof count other than the peak count the origin size implies
// is rejected. Size 4 has two peaks.
func TestConsistentRootsForSizesRejectsPeakCountMismatch(t *testing.T) {
	db := NewCanonicalTestDB(t)
	hasher := sha256.New()

	accFrom := [][]byte{db.mustGet(2), db.mustGet(3)}
	proofs := [][][]byte{{db.mustGet(5)}, {db.mustGet(4), db.mustGet(2)}}

	_, _, err := ConsistentRootsForSizes(hasher, 4, 7, accFrom[:1], proofs)
	require.ErrorIs(t, err, ErrConsistencyPeakCount)
	_, _, err = ConsistentRootsForSizes(hasher, 4, 7, accFrom, proofs[:1])
	require.ErrorIs(t, err, ErrConsistencyPeakCount)
}

// TestConsistentRootsForSizesKAT39Vectors pins the literal vectors shared with
// the solidity and python suites for the same algorithm over the canonical 39
// node MMR. The values are written out rather than read from the db so that a
// change to any one implementation's tree building is visible here.
func TestConsistentRootsForSizesKAT39Vectors(t *testing.T) {
	hasher := sha256.New()

	tests := []struct {
		name     string
		sizeFrom uint64
		sizeTo   uint64
		accFrom  []string
		proofs   [][]string
		roots    []string
		right    int
	}{
		{
			// one peak to one peak: the leaf at index 0 climbs to peak 2.
			name:     "1 to 3",
			sizeFrom: 1,
			sizeTo:   3,
			accFrom:  []string{"af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc"},
			proofs: [][]string{
				{"cd2662154e6d76b2b2b92e70c0cac3ccf534f9b74eb5b89819ec509083d00a50"},
			},
			roots: []string{"ad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8"},
			right: 0,
		},
		{
			// two origin peaks under one target peak: both paths prove peak 6,
			// so a single root is returned.
			name:     "4 to 7",
			sizeFrom: 4,
			sizeTo:   7,
			accFrom: []string{
				"ad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8",
				"d5688a52d55a02ec4aea5ec1eadfffe1c9e0ee6a4ddbe2377f98326d42dfc975",
			},
			proofs: [][]string{
				{"9a18d3bc0a7d505ef45f985992270914cc02b44c91ccabba448c546a4b70f0f0"},
				{
					"8005f02d43fa06e7d0585fb64c961d57e318b27a145c857bcd3a6bdb413ff7fc",
					"ad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8",
				},
			},
			roots: []string{"827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88"},
			right: 0,
		},
		{
			// the paths have the lengths the heights imply: 1 for the peak at
			// height 2 and 3 for the leaf peak.
			name:     "8 to 15",
			sizeFrom: 8,
			sizeTo:   15,
			accFrom: []string{
				"827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88",
				"a3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2",
			},
			proofs: [][]string{
				{"508326f17c5f2769338cb00105faba3bf7862ca1e5c9f63ba2287e1f3cf2807a"},
				{
					"4c0e071832d527694adea57b50dd7b2164c2a47c02940dcf26fa07c44d6d222a",
					"6f3360ad3e99ab4ba39f2cbaf13da56ead8c9e697b03b901532ced50f7030fea",
					"827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88",
				},
			},
			roots: []string{"78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112"},
			right: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accFrom := make([][]byte, len(tt.accFrom))
			for i, value := range tt.accFrom {
				accFrom[i] = mustHex2Hash(t, value)
			}
			proofs := make([][][]byte, len(tt.proofs))
			for i, path := range tt.proofs {
				proofs[i] = make([][]byte, len(path))
				for j, value := range path {
					proofs[i][j] = mustHex2Hash(t, value)
				}
			}
			want := make([][]byte, len(tt.roots))
			for i, value := range tt.roots {
				want[i] = mustHex2Hash(t, value)
			}

			roots, expectedRight, err := ConsistentRootsForSizes(
				hasher, tt.sizeFrom, tt.sizeTo, accFrom, proofs)
			require.NoError(t, err)
			assert.Equal(t, want, roots)
			assert.Equal(t, tt.right, expectedRight)
		})
	}
}

// TestMMRSizeForLeafCountIdentity checks that
// MMRSizeForLeafCount(PeaksBitmap(size)) == size holds for exactly the complete
// sizes of the canonical 39 node MMR. That identity is the completeness test
// applied to the target size.
func TestMMRSizeForLeafCountIdentity(t *testing.T) {
	complete := make(map[uint64]bool, len(KAT39CompleteMMRSizes))
	for i, size := range KAT39CompleteMMRSizes {
		complete[size] = true
		// the i'th complete size holds i+1 leaves
		assert.Equal(t, size, MMRSizeForLeafCount(uint64(i+1)))
	}

	for size := uint64(1); size <= KAT39CompleteMMRSizes[len(KAT39CompleteMMRSizes)-1]; size++ {
		assert.Equal(t, complete[size],
			MMRSizeForLeafCount(PeaksBitmap(size)) == size, "size %d", size)
	}
}

// TestConsistentRootsForSizesErrorsAreDistinct checks each condition reports
// its own sentinel, so callers can tell the shape checks apart.
func TestConsistentRootsForSizesErrorsAreDistinct(t *testing.T) {
	for _, err := range []error{
		ErrSizesNotIncreasing, ErrIncompleteTreeSize,
		ErrConsistencyPeakCount, ErrConsistencyPathLength,
		ErrConsistencyRootMismatch,
	} {
		require.False(t, errors.Is(err, ErrAccumulatorProofLen))
	}
}

// VerifyConsistency routes through ConsistentRootsForSizes for growing sizes
// and treats equal sizes as one state: every path empty, target peaks equal
// origin peaks. GetContextVerified reaches the equal case whenever a massif
// has not grown past its seal.
func TestVerifyConsistencyEqualSizesIsIdentity(t *testing.T) {
	db := NewCanonicalTestDB(t)
	hasher := sha256.New()
	for _, i := range KAT39CompleteMMRIndices {
		cp, err := IndexConsistencyProof(db, i, i)
		require.NoError(t, err)
		peaks, err := PeakHashes(db, i)
		require.NoError(t, err)

		ok, got, err := VerifyConsistency(hasher, cp, peaks, peaks)
		require.NoError(t, err, "size %d", i+1)
		assert.True(t, ok)
		assert.Equal(t, peaks, got)

		// A replaced target peak is rejected.
		altered := make([][]byte, len(peaks))
		copy(altered, peaks)
		altered[len(altered)-1] = replacementHash(0xff)
		_, _, err = VerifyConsistency(hasher, cp, peaks, altered)
		assert.ErrorIs(t, err, ErrConsistencyCheck, "size %d", i+1)

		// A non-empty path where the sizes imply none is rejected.
		surplus := copyProofPaths(cp.Path)
		surplus[0] = append(surplus[0], replacementHash(0x00))
		_, _, err = VerifyConsistency(hasher, ConsistencyProof{
			MMRSizeA: cp.MMRSizeA, MMRSizeB: cp.MMRSizeB, Path: surplus,
		}, peaks, peaks)
		assert.ErrorIs(t, err, ErrConsistencyPathLength, "size %d", i+1)
	}
}

// VerifyConsistency rejects a target size that is not a complete mmr size and
// a target accumulator with a surplus entry; both are outside the shape the
// sizes imply.
func TestVerifyConsistencyRejectsOffShapeTarget(t *testing.T) {
	db := NewCanonicalTestDB(t)
	hasher := sha256.New()
	cp, err := IndexConsistencyProof(db, 2, 6)
	require.NoError(t, err)
	peaksFrom, err := PeakHashes(db, 2)
	require.NoError(t, err)
	peaksTo, err := PeakHashes(db, 6)
	require.NoError(t, err)

	_, _, err = VerifyConsistency(hasher, ConsistencyProof{
		MMRSizeA: 3, MMRSizeB: 6, Path: cp.Path,
	}, peaksFrom, peaksTo)
	assert.ErrorIs(t, err, ErrIncompleteTreeSize)

	_, _, err = VerifyConsistency(hasher, cp, peaksFrom, append(peaksTo, replacementHash(0x01)))
	assert.ErrorIs(t, err, ErrConsistencyCheck)
}
