package massifs

import (
	"testing"

	"github.com/forestrie/go-merklelog/mmr"
)

// massifIndexKAT is the leaf index -> massif index known-answer table. The
// same table is pinned in canopy (@forestrie/merklelog
// test/massifs/massifindex.test.ts) and in arbor's ranger, so Go and TS agree
// that a massif of one-based height h holds 2^(h-1) leaves.
var massifIndexKAT = []struct {
	massifHeight uint8
	leafIndex    uint64
	massifIndex  uint64
}{
	{1, 0, 0}, {1, 1, 1}, {1, 2, 2},
	{2, 0, 0}, {2, 1, 0}, {2, 2, 1}, {2, 3, 1},
	{3, 3, 0}, {3, 4, 1},
	{14, 0, 0}, {14, 8191, 0}, {14, 8192, 1}, {14, 16383, 1}, {14, 16384, 2},
}

func TestMassifIndexFromLeafIndexKAT(t *testing.T) {
	for _, tc := range massifIndexKAT {
		if got := MassifIndexFromLeafIndex(tc.massifHeight, tc.leafIndex); got != tc.massifIndex {
			t.Errorf("MassifIndexFromLeafIndex(h=%d, leaf=%d) = %d, want %d",
				tc.massifHeight, tc.leafIndex, got, tc.massifIndex)
		}
		if got := MassifFromLeaf(tc.massifHeight, tc.leafIndex); got != tc.massifIndex {
			t.Errorf("MassifFromLeaf(h=%d, leaf=%d) = %d, want %d",
				tc.massifHeight, tc.leafIndex, got, tc.massifIndex)
		}
		if got := MassifIndexFromMMRIndex(tc.massifHeight, mmr.MMRIndex(tc.leafIndex)); got != tc.massifIndex {
			t.Errorf("MassifIndexFromMMRIndex(h=%d, leaf=%d) = %d, want %d",
				tc.massifHeight, tc.leafIndex, got, tc.massifIndex)
		}
	}
}
