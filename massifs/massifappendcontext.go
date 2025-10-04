package massifs

import (
	"context"
	"errors"
	"fmt"

	"github.com/datatrails/go-datatrails-merklelog/massifs/storage"
	"github.com/datatrails/go-datatrails-merklelog/mmr"
)

// GetAppendContext implements the unified logic for getting an append context
func GetAppendContext(
	ctx context.Context, reader ObjectReader, epoch uint32, massifHeight uint8,
) (MassifContext, error) {

	mc, err := GetMassifHeadContext(ctx, reader)
	if errors.Is(err, storage.ErrLogEmpty) {
		mc, err := CreateFirstMassifContext(ctx, epoch, massifHeight)
		if err != nil {
			return MassifContext{}, fmt.Errorf("failed to create first massif context: %w", err)
		}
		return mc, nil
	}
	if err != nil {
		return MassifContext{}, fmt.Errorf("failed to get massif head context: %w", err)
	}
	if err = InitAppendContext(ctx, reader, &mc); err != nil {
		return MassifContext{}, fmt.Errorf("failed to init append context: %w", err)
	}
	return mc, nil
}

// CommitContext implements the unified logic for committing a massif context
func CommitContext(ctx context.Context, writer ObjectWriter, mc *MassifContext) error {

	// Check we have not over filled the massif.
	// Note that we need to account for the size based on the full range. When
	// committing massifs after the first, additional nodes are always required to
	// "bury", the previous massif's nodes.

	// leaves that the height (not the height index) allows for.
	maxLeafIndex := ((mmr.HeightSize(uint64(mc.Start.MassifHeight))+1)>>1)*uint64(mc.Start.MassifIndex+1) - 1
	spurHeight := mmr.SpurHeightLeaf(maxLeafIndex)
	// The overall size of the massif that contains that many leaves.
	maxMMRSize := mmr.MMRIndex(maxLeafIndex) + spurHeight + 1

	count := mc.Count()

	// The last legal index is first leaf + count - 1. The last leaf index + the
	// height is the last node index + 1. So we just don't subtract the one on
	// either clause.
	if mc.Start.FirstIndex+count > maxMMRSize {
		return ErrMassifFull
	}

	err := writer.Put(ctx, mc.Start.MassifIndex, storage.ObjectMassifData, mc.Data, mc.Creating)

	mc.Creating = false

	return err
}

// InitAppendContext checks if the massif context needs to be rolled over to a new
// massif and does so if required.
func InitAppendContext(ctx context.Context, reader ObjectReader, mc *MassifContext) error {

	var err error

	// Size checking logic (identical for all storages)
	sz := TreeSize(mc.Start.MassifHeight)
	start := mc.LogStart()
	if uint64(len(mc.Data))-start < sz {
		return nil
	}

	// Need new massif (logic identical for all storages)
	mc.Creating = true
	err = mc.StartNextMassif()
	if err != nil {
		return fmt.Errorf("failed to start next massif: %w", err)
	}

	// Create peak stack map for new massif
	if err = mc.CreatePeakStackMap(); err != nil {
		return fmt.Errorf("failed to create peak stack map (new massif): %w", err)
	}

	return nil
}

// CreateFirstMassifContext creates the context for the very first massif
func CreateFirstMassifContext(ctx context.Context, epoch uint32, massifHeight uint8) (MassifContext, error) {
	start := NewMassifStart(0, epoch, massifHeight, 0, 0)

	data, err := start.MarshalBinary()
	if err != nil {
		return MassifContext{}, fmt.Errorf("failed to marshal first massif start: %w", err)
	}

	mc := MassifContext{
		Creating: true,
		Start:    start,
	}

	// Pre-allocate and zero-fill the index
	data = append(data, mc.InitIndexData()...)
	mc.Data = data

	// Create peak stack map for sequencers that need it
	if err := mc.CreatePeakStackMap(); err != nil {
		return MassifContext{}, fmt.Errorf("failed to create peak stack map for first massif: %w", err)
	}

	return mc, nil
}
