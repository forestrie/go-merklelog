package massifs

import (
	"context"

	"github.com/datatrails/go-datatrails-merklelog/massifs/storage"
)

type ObjectReader interface {
	HeadIndex(ctx context.Context, otype storage.ObjectType) (uint32, error)

	MassifData(massifIndex uint32) ([]byte, bool, error)
	CheckpointData(massifIndex uint32) ([]byte, bool, error)

	// MassifReadN un-conditionally reads up to n bytes of the massif data The read
	// data is both cached and returned. Subsequent calls to MassifData will return
	// the cached data.
	// n = -1 means no limit, read all available
	MassifReadN(ctx context.Context, massifIndex uint32, n int) ([]byte, error)
	CheckpointRead(ctx context.Context, massifIndex uint32) ([]byte, error)
}

type ObjectWriter interface {
	Put(ctx context.Context, massifIndex uint32, ty storage.ObjectType, data []byte, failIfExists bool) error
}

type ObjectReaderWriter interface {
	ObjectReader
	ObjectWriter
}
