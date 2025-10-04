package storage

import (
	"fmt"
)

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

func ObjectPath(prefix string, logID LogID, massifIndex uint32, otype ObjectType) (string, error) {

	switch otype {
	case ObjectPathMassifs, ObjectPathCheckpoints:
		return prefix, nil
	case ObjectCheckpoint:
		return FmtCheckpointPath(prefix, massifIndex), nil
	case ObjectMassifStart:
		fallthrough
	case ObjectMassifData:
		fallthrough
	default:
		return FmtMassifPath(prefix, massifIndex), nil
	}
}

// GetObjectIndex returns the index of the object in the storage path for the given object type.
// It returns an error if the storage path does not match the expected format for the object type.
func GetObjectIndex(storagePath string, otype ObjectType) (uint32, error) {
	gotOType, massifIndex, err := ObjectIndexFromPath(storagePath)
	if err != nil {
		return ^uint32(0), fmt.Errorf("failed to get object index from path %s: %w", storagePath, err)
	}
	if otype != gotOType {
		return ^uint32(0), fmt.Errorf("object type mismatch: expected %v, got %v", otype, gotOType)
	}
	return massifIndex, nil
}
