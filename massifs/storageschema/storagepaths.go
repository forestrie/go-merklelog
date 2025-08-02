package storageschema

import (
	"fmt"

	"github.com/datatrails/go-datatrails-merklelog/massifs/storage"
)

type StoragePaths struct {
	PrefixProvider PrefixProvider
	CurrentLogID   storage.LogID
}

func FmtMassifPath(prefix string, massifIndex uint32) string {
	return fmt.Sprintf(
		"%s%s", prefix, fmt.Sprintf(V1MMRBlobNameFmt, massifIndex),
	)
}
func FmtCheckpointPath(prefix string, massifIndex uint32) string {
	return fmt.Sprintf(
		"%s%s", prefix, fmt.Sprintf(V1MMRSignedTreeHeadBlobNameFmt, massifIndex),
	)
}
func (s *StoragePaths) SelectLog(logID storage.LogID) error {
	s.CurrentLogID = logID
	return nil
}

func (s StoragePaths) GetStoragePrefix(otype storage.ObjectType) (string, error) {
	return s.GetLogStoragePrefix(s.CurrentLogID, otype)
}

func (s StoragePaths) GetStoragePath(massifIndex uint32, otype storage.ObjectType) (string, error) {
	return s.GetLogStoragePath(s.CurrentLogID, massifIndex, otype)
}

func (s StoragePaths) GetLogStoragePrefix(logID storage.LogID, otype storage.ObjectType) (string, error) {
	return s.PrefixProvider.Prefix(logID, otype)
}

func (s StoragePaths) GetLogStoragePath(logID storage.LogID, massifIndex uint32, otype storage.ObjectType) (string, error) {

	prefix, err := s.PrefixProvider.Prefix(logID, otype)
	if err != nil {
		return "", err
	}
	switch otype {
	case storage.ObjectPathMassifs, storage.ObjectPathCheckpoints:
		return prefix, nil
	case storage.ObjectCheckpoint:
		return FmtCheckpointPath(prefix, massifIndex), nil
	case storage.ObjectMassifStart:
		fallthrough
	case storage.ObjectMassifData:
		fallthrough
	default:
		return FmtMassifPath(prefix, massifIndex), nil
	}
}

func (s StoragePaths) GetObjectLogID(storagePath string) (storage.LogID, error) {
	return s.PrefixProvider.LogID(storagePath)
}

// GetPathObjectIndex returns the object type and index from the storage path
// It returns an error if the object type can not be determined from the path.
func (s StoragePaths) GetPathObjectIndex(storagePath string) (storage.ObjectType, uint32, error) {
	return ObjectIndexFromPath(storagePath)
}

// GetObjectIndex returns the index of the object in the storage path for the given object type.
// It returns an error if the storage path does not match the expected format for the object type.
func (s StoragePaths) GetObjectIndex(storagePath string, otype storage.ObjectType) (uint32, error) {
	gotOType, massifIndex, err := ObjectIndexFromPath(storagePath)
	if err != nil {
		return ^uint32(0), fmt.Errorf("failed to get object index from path %s: %w", storagePath, err)
	}
	if otype != gotOType {
		return ^uint32(0), fmt.Errorf("object type mismatch: expected %v, got %v", otype, gotOType)
	}
	return massifIndex, nil
}
