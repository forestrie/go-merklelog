// Package storage provides an interface for reading logs from a path based storage system
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

type IdentifyLogFunc func(ctx context.Context, storagePath string) (LogID, error)

type SelectableLog interface {
	IdentifyLog(ctx context.Context, storagePath string) (LogID, error)
	SelectLog(LogID) error
}

type ObjectExtents interface {
	// Extents return the max, min massif indices for the current selected log
	// an the provided object type. The extents for start and massif are always
	// the same, but the checkpoint may be different.
	// Notice: if there is no log selected, the extents are undefined and (0, 0) is returned.
	Extents(ty ObjectType) (uint32, uint32)
	HeadIndex(ctx context.Context, ty ObjectType) (uint32, error)
}

type ObjectIndexer interface {
	ObjectIndex(storagePath string, ty ObjectType) (uint32, error)
	// DropIndex drops any cached representation for the specificed object type.
	// If implementations have no specific action for the given type, they should
	// drop all cached data for the provided index
	DropIndex(index uint32, ty ObjectType)
}

// ObjectNatives is supported by providers that need to export native
// representations. The caller needs to know the appropriate type assertion.
type ObjectNatives interface {
	Native(massifIndex uint32, ty ObjectType) (any, error)
}

type CachingReader interface {
	// Prime is used to lazily prepare the cache for satisfying Get's
	// Implementations may decide to read the data immediately depending on its knowledge of the type
	Prime(ctx context.Context, storagePath string, ty ObjectType) error
}

type ObjectReader interface {
	// Read reads the data from the storage path and returns an error if it fails.
	// Any cached values must be updated by implementations.
	Read(ctx context.Context, storagePath string, ty ObjectType) error
}

type MassifReader interface {
	// GetStart retrieves the start of a massif by its index.
	// But does not trigger a read of the massif data.
	GetStart(ctx context.Context, massifIndex uint32) (massifs.MassifStart, error)

	GetData(ctx context.Context, massifIndex uint32) ([]byte, error)

	// Get retrieves the massif start and data by its index.
	GetMassifContext(ctx context.Context, massifIndex uint32) (massifs.MassifContext, error)

	// GetHeadContex returns a context for the largest available massif index
	GetHeadContext(ctx context.Context) (massifs.MassifContext, error)
}

type CheckpointReader interface {
	GetCheckpoint(ctx context.Context, massifIndex uint32) (*massifs.Checkpoint, error)
}

type UnverifiedMassifReader interface {
	// Get retrieves the massif start, data, and checkpoint by its index.
	// This will trigger a read of the massif data, if it is not already cached.
	GetUnverified(ctx context.Context, massifIndex uint32) ([]byte, massifs.MassifStart, *massifs.Checkpoint, error)
}

type VerifiedMassifReader interface {
	// Get retrieves the massif start, data, and checkpoint by its index.
	// This will trigger a read of the massif data, if it is not already cached.
	GetVerified(ctx context.Context, massifIndex uint32) ([]byte, massifs.MassifStart, *massifs.Checkpoint, error)
}

type Reader interface {
	SelectableLog
	ObjectIndexer
	ObjectExtents
	ObjectReader
	MassifReader
	UnverifiedMassifReader
}
