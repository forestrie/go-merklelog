// Package storage provides an interface for reading logs from a path based storage system
package storage

import (
	"context"
)

type ObjectType uint8

const (
	ObjectUndefined ObjectType = iota
	ObjectMassifStart
	ObjectMassifData
	ObjectCheckpoint
	ObjectPathMassifs
	ObjectPathCheckpoints
)

const (
	HeadMassifIndex = ^uint32(0)
)

// type IdentifyLogFunc func(ctx context.Context, storagePath string) (LogID, error)

type PathProvider interface {
	SelectLog(ctx context.Context, logID LogID) error
	GetStoragePrefix(otype ObjectType) (string, error)
	GetObjectIndex(storagePath string, otype ObjectType) (uint32, error)
	GetStoragePath(massifIndex uint32, otype ObjectType) (string, error)
}

// StorageFeature represents storage-specific capabilities
type StorageFeature int

const (
	// OptimisticWrite indicates support for optimistic concurrency control on writes
	OptimisticWrite StorageFeature = iota
	// TagBasedFiltering indicates support for filtering objects based on metadata tags
	TagBasedFiltering
	// BulkOperations indicates support for batch/bulk operations
	BulkOperations
)
