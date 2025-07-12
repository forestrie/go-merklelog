package storage

import "github.com/datatrails/go-datatrails-merklelog/massifs"

type Cacher interface {
	Reader

	// Set establishes the massif data at the given storage path, without
	// writing back to the underlying storage.  Note that the start is
	// automatically obtained from the data.
	SetData(storagePath string, massifIndex uint32, data []byte) error
	SetCheckpoint(storagePath string, massifIndex uint32, checkpt *massifs.Checkpoint) error

	Update(massifIndex uint32, data []byte, start massifs.MassifStart, checkpoint *massifs.Checkpoint) error

	// Write the current cached value back to its current storage location
	WriteThrough(massifIndex uint32) error
}
