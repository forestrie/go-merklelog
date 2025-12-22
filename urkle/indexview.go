package urkle

import "fmt"

// IndexView is a zero-allocation view over an on-disk urkle index payload.
//
// In this rollout, indexData is assumed to be exactly:
//   leafTable || nodeStore
//
// where:
//   - leafTableBytes = leafCount * LeafRecordBytes
//   - nodeStoreBytes = (2*leafCount-1) * NodeRecordBytes
//
// leafCount is the fixed leaf capacity N for the chunk (e.g. derived from massifHeight).
type IndexView struct {
	LeafCount uint64
	LeafTable []byte
	NodeStore []byte
}

// NewIndexView slices indexData into (leafTable,nodeStore) according to leafCount.
func NewIndexView(indexData []byte, leafCount uint64) (IndexView, error) {
	if err := CheckLeafCount(leafCount); err != nil {
		return IndexView{}, err
	}
	if leafCount == 0 {
		return IndexView{}, fmt.Errorf("%w: leafCount must be > 0", ErrLeafTableBadSize)
	}

	leafTableBytes := LeafTableBytes(leafCount)
	nodeStoreBytes := NodeStoreBytes(leafCount)

	total := leafTableBytes + nodeStoreBytes
	if uint64(len(indexData)) != total {
		return IndexView{}, fmt.Errorf(
			"%w: bad indexData size: want=%d, got=%d",
			ErrNodeStoreBadSize, total, len(indexData),
		)
	}

	lt := indexData[:leafTableBytes]
	ns := indexData[leafTableBytes:]
	return IndexView{
		LeafCount: leafCount,
		LeafTable: lt,
		NodeStore: ns,
	}, nil
}

// NewIndexViewFromMassifHeight slices indexData into (leafTable,nodeStore) using the fixed
// leaf capacity derived from massifHeight (one-based).
func NewIndexViewFromMassifHeight(indexData []byte, massifHeight uint8) (IndexView, error) {
	leafCount := LeafCountForMassifHeight(massifHeight)
	return NewIndexView(indexData, leafCount)
}


