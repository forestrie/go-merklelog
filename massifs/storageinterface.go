package massifs

import (
	"context"
)

type MassifReader interface {
	// GetStart retrieves the start of a massif by its index.
	// But does not trigger a read of the massif data.
	GetStart(ctx context.Context, massifIndex uint32) (*MassifStart, error)

	GetData(ctx context.Context, massifIndex uint32) ([]byte, error)
}

type MassifContextReader interface {
	// GetMassifContext retrieves the massif context by its index.
	GetMassifContext(ctx context.Context, massifIndex uint32) (*MassifContext, error)

	// GetHeadContext returns a context for the largest available massif index
	GetHeadContext(ctx context.Context) (*MassifContext, error)
}

type MassifCommitter interface {
	// GetAppendContext returns the next append ready massif context for the log
	GetAppendContext(ctx context.Context) (*MassifContext, error)
	CommitContext(ctx context.Context, mc *MassifContext) error
}

type CheckpointReader interface {
	GetCheckpoint(ctx context.Context, massifIndex uint32) (*Checkpoint, error)
}

type CheckpointContextReader interface {
	MassifContextReader
	CheckpointReader
}

type VerifiedMassifReader interface {
	GetContextVerified(ctx context.Context, massifIndex uint32, opts ...Option) (*VerifiedContext, error)
	GetHeadContextVerified(ctx context.Context, opts ...Option) (*VerifiedContext, error)
}
