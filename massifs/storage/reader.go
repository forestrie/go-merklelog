package storage

import (
	"context"

	"github.com/datatrails/go-datatrails-merklelog/massifs"
)

type ObjectType uint8

const (
	ObjectUndefined ObjectType = iota
	ObjectMassifStart
	ObjectMassifData
	ObjectCheckpoint
	ObjectMassifsRoot
	ObjectCheckpointsRoot
)

const (
	HeadMassifIndex = ^uint32(0)
)

type IdentifyLogFunc func(ctx context.Context, storagePath string) (LogId, error)

type Reader interface {
	IdentifyLog(ctx context.Context, storagePath string) (LogId, error)
	SelectLog(LogId) error

	// Extents return the max, min massif indices for the current selected log
	// an the provided object type. The extents for start and massif are always
	// the same, but the checkpoint may be different.
	// Notice: if there is no log selected, the extents are undefined and (0, 0) is returned.
	Extents(ty ObjectType) (uint32, uint32)

	// Prime is used to lazily prepare the cache for satisfying Get's
	// Implementations may decide to read the data immediately depending on its knowledge of the type
	Prime(ctx context.Context, storagePath string, ty ObjectType) error

	// Read reads the data from the storage path and returns an error if it fails.
	// Any cached values must be updated by implementations.
	Read(ctx context.Context, storagePath string, ty ObjectType) error

	// GetStart retrieves the start of a massif by its index.
	// But does not trigger a read of the massif data.
	GetStart(ctx context.Context, massifIndex uint32) (massifs.MassifStart, error)

	GetData(ctx context.Context, massifIndex uint32) ([]byte, error)
	GetCheckpoint(ctx context.Context, massifIndex uint32) (*massifs.Checkpoint, error)

	// Get retrieves the massif start, data, and checkpoint by its index.
	// This will trigger a read of the massif data, if it is not already cached.
	Get(ctx context.Context, massifIndex uint32) ([]byte, massifs.MassifStart, *massifs.Checkpoint, error)
}
