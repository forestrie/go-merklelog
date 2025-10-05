package massifs

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/forestrie/go-merklelog/mmr"
	"github.com/stretchr/testify/assert"
)

func TestPeakStackMap(t *testing.T) {
	type args struct {
		massifHeight uint8
		mmrIndex     uint64
	}
	tests := []struct {
		name string
		args args
		want map[uint64]int
	}{
		// Note that the mmrSize used here, is also the FirstLeaf + 1 of the
		// massif containing the peak stack.
		{"massifpeakstack_test:0", args{2, 0}, map[uint64]int{}},
		{"massifpeakstack_test:1", args{2, 3}, map[uint64]int{
			2: 0,
		}},
		{"massifpeakstack_test:2", args{2, 6}, map[uint64]int{
			6: 0,
		}},

		{"massifpeakstack_test:3", args{2, 9}, map[uint64]int{
			6: 0,
			9: 1,
		}},
		{"massifpeakstack_test:4", args{2, 14}, map[uint64]int{
			14: 0,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PeakStackMap(tt.args.massifHeight, tt.args.mmrIndex); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PeakStackMap() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestPeakStackPopArithmetic tests that the primitive methods the massif peak stack
// relies on and the arithmetic for maintaining the stack are consistent.
func TestPeakStackPopArithmetic(t *testing.T) {
	// Working with height 1 massifs and the following overall MMR
	//
	//  4                        30
	//
	//
	//               14                        29
	//	3           /  \                      /   \
	//	           /    \                    /     \
	//	          /      \                  /       \
	//	         /        \                /         \
	//	2      6 .      .  13             21          28
	//	      /   \       /   \          /  \        /   \
	//	1    2  |  5  |  9  |  12   |  17  | 20   | 24   | 27   |  --- massif tree line massif height = 1
	//	    / \ |/  \ | / \ |  /  \ | /  \ | / \  | / \  | / \  |
	//	   0   1|3   4|7   8|10   11|15  16|18  19|22  23|25  26| MMR INDICES
	//     -----|-----|-----|-------|------|------|------|------|
	//	   0 . 1|2 . 3|4   5| 6    7| 8   9|10  11|12  13|14  15| LEAF INDICES
	//     -----|-----|-----|-------|------|------|------|------|
	//       0  |  1  |  2  |  3    |   4  |   5  |   6  |   7  | MASSIF INDICES
	//     -----|-----|-----|-------|------|------|------|------|

	// height, a 3 node tree has height 2 (some places we use a height index)
	massifHeight := uint64(2) // each masif has 2 leaves and 3 nodes + spur
	massifNodeCount := uint64((1 << massifHeight) - 1)
	massifLeafCount := (massifNodeCount + 1) / 2

	stack := []uint64{}

	expectStacks := [][]uint64{
		{uint64(2)},
		{uint64(6)},
		{uint64(6), uint64(9)},
		{uint64(14)},
		{uint64(14), uint64(17)},
		{uint64(14), uint64(21)},
		{uint64(14), uint64(21), uint64(24)},
		{uint64(30)},
	}

	for massifIndex := range uint64(8) {
		t.Run(fmt.Sprintf("iLeaf:%d", massifIndex), func(t *testing.T) {
			// this shows that we can work with massif indices as tho they were
			// leaf indices. the only point the difference between leaf and
			// massif blob index matters is where we calculate the MMR index of
			// the node we are putitng on the stack. We never explicitly
			// calculate the index of the node being added, we just add it, its
			// the arithmetic for 'popping' the stack we care about. We track
			// the implied node indices here only for the purpose of the test.
			//
			// Note in particular, any node that gets into the stack is always
			// the *last* node from a particular massif blob. The peak nodes we
			// need to reference in future blobs are *always* last leafs from
			// some preceding blob. The MMR structure means there are 'interior'
			// peaks, but those are only referenced within that particular blob.

			lastLeaf := massifIndex*massifLeafCount + massifLeafCount - 1
			spurHeightLeaf := mmr.SpurHeightLeaf(lastLeaf)
			iPeak := mmr.MMRIndex(lastLeaf) + spurHeightLeaf

			stackLen := mmr.LeafMinusSpurSum(massifIndex)

			// we push for current leaf and pop for previous
			pop := mmr.SpurHeightLeaf(massifIndex)

			fmt.Printf("-----: L=%02d LL=%02d P=%d, StackLen=%d, pop=%d\n", massifIndex, lastLeaf, iPeak, stackLen, pop)
			fmt.Printf("stack:%v\n", stack)
			assert.Equal(t, stackLen, uint64(len(stack)))

			stack = stack[:len(stack)-int(pop)]
			// stack = append(stack, iPeak)
			stack = append(stack, iPeak)

			// Check we produced the expected stack for the next round. Note
			// that each time we start a new blob in StartNextMassif, we have
			// just read the previous and discovered that it is full. So this
			// corresponds to creating the stack for the *new* blob based on the
			// full blob we have in our hand.
			assert.Equal(t, expectStacks[massifIndex], stack)
			// fmt.Printf("i=%02d push(%d) pop-len %d: %v %v %v\n", leafIndex, iRoot, pop, stackBefore, stackPop, stack)
			// fmt.Printf("after:i=%02d r=%d: %v %v %v\n", leafIndex, iRoot, stackBefore, stackPop, stack)
		})
	}
}
