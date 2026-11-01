package massifs

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/forestrie/go-merklelog/mmr"
	"github.com/forestrie/go-merklelog/urkle"
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

// TestMassifRollsOverAfterOneBasedHeightLeaves appends leaves to a real first
// massif and checks where it fills, so the KAT above is anchored to what the
// writer does rather than to the division helpers alone: a massif of height h
// accepts exactly 2^(h-1) leaves, then returns ErrMassifFull.
func TestMassifRollsOverAfterOneBasedHeightLeaves(t *testing.T) {
	for _, h := range []uint8{1, 2, 3, 5, 8} {
		mc, err := CreateFirstMassifContext(context.Background(), 1, h)
		if err != nil {
			t.Fatalf("h=%d: CreateFirstMassifContext: %v", h, err)
		}
		want := uint64(1) << (h - 1)
		value := sha256.Sum256([]byte("leaf"))

		var leaves uint64
		for {
			if _, err := mc.AddIndexedEntry(value[:]); err != nil {
				if !errors.Is(err, ErrMassifFull) {
					t.Fatalf("h=%d leaf %d: %v", h, leaves, err)
				}
				break
			}
			leaves++
			if leaves > 2*want {
				t.Fatalf("h=%d: massif never filled after %d leaves", h, leaves)
			}
		}

		if leaves != want {
			t.Errorf("h=%d: massif held %d leaves, want 2^(h-1) = %d", h, leaves, want)
		}
		if got := urkle.LeafCountForMassifHeight(h); got != leaves {
			t.Errorf("h=%d: LeafCountForMassifHeight = %d, writer held %d", h, got, leaves)
		}
		if got := MassifIndexFromLeafIndex(h, leaves); got != 1 {
			t.Errorf("h=%d: first leaf past the full massif maps to massif %d, want 1", h, got)
		}
	}
}
