package massifs

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/forestrie/go-merklelog/mmr"
	"github.com/stretchr/testify/require"
)

type memNodes struct{ nodes [][]byte }

func (m *memNodes) Get(i uint64) ([]byte, error) {
	if i >= uint64(len(m.nodes)) {
		return nil, fmt.Errorf("index %d out of range", i)
	}
	return m.nodes[i], nil
}

func (m *memNodes) Append(value []byte) (uint64, error) {
	m.nodes = append(m.nodes, value)
	return uint64(len(m.nodes)), nil
}

func newFixtureMMR(t *testing.T, nLeaves int) (*memNodes, []uint64) {
	t.Helper()
	store := &memNodes{}
	sizes := make([]uint64, 0, nLeaves)
	h := sha256.New()
	for i := 0; i < nLeaves; i++ {
		leaf := sha256.Sum256([]byte{byte(i)})
		size, err := mmr.AddHashedLeaf(store, h, leaf[:])
		require.NoError(t, err)
		sizes = append(sizes, size)
	}
	return store, sizes
}

// reconstructAccumulator applies the proof the way the contract does: the
// consistent roots from the paths, then the right-peaks appended.
func reconstructAccumulator(t *testing.T, store *memNodes, p ConsistencyProof) [][]byte {
	t.Helper()
	if p.TreeSize1 == 0 {
		return p.RightPeaks
	}
	peaksFrom, err := mmr.PeakHashes(store, p.TreeSize1-1)
	require.NoError(t, err)
	roots, err := mmr.ConsistentRoots(sha256.New(), p.TreeSize1-1, peaksFrom, p.Paths)
	require.NoError(t, err)
	return append(roots, p.RightPeaks...)
}

func TestBuildConsistencyProofReachesTargetAccumulator(t *testing.T) {
	store, sizes := newFixtureMMR(t, 8)
	sizeA, sizeB := sizes[3], sizes[6]

	proof, err := BuildConsistencyProof(store, sizeA, sizeB)
	require.NoError(t, err)
	require.Equal(t, sizeA, proof.TreeSize1)
	require.Equal(t, sizeB, proof.TreeSize2)

	peaksB, err := mmr.PeakHashes(store, sizeB-1)
	require.NoError(t, err)
	require.Equal(t, peaksB, reconstructAccumulator(t, store, proof))
}

func TestBuildConsistencyProofFirstCheckpointIsRightPeaksOnly(t *testing.T) {
	store, sizes := newFixtureMMR(t, 2)

	proof, err := BuildConsistencyProof(store, 0, sizes[1])
	require.NoError(t, err)
	require.Equal(t, uint64(0), proof.TreeSize1)
	require.Empty(t, proof.Paths)

	peaks, err := mmr.PeakHashes(store, sizes[1]-1)
	require.NoError(t, err)
	require.Equal(t, peaks, proof.RightPeaks)
}
