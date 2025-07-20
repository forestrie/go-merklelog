package storageschema

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/datatrails/go-datatrails-merklelog/massifs/storage"
)

// FixedPaths impelments the schema interface where the storage is fixed to
// as single log
type FixedPaths struct {
	MassifsRoot     string
	CheckpointsRoot string
}

type Paths struct {
	PrefixProvider PrefixProvider
}

func massifIndexFromPath(storagePath string) (uint32, error) {
	var err error
	// ensure it doesn't end with a slash
	storagePath = strings.TrimSuffix(storagePath, "/")
	i := strings.LastIndex(storagePath, "/")
	baseName := storagePath[i+1:]

	for _, suffix := range []string{
		V1MMRExtSep + V1MMRMassifExt,
		V1MMRExtSep + V1MMRSealSignedRootExt,
	} {
		if !strings.HasSuffix(baseName, suffix) {
			continue
		}
		i, err = strconv.Atoi(baseName[:len(baseName)-len(suffix)])
		if err != nil {
			return ^uint32(0), err
		}
		return uint32(i), nil

	}
	return ^uint32(0), fmt.Errorf("path %s has no recognisable object suffix", storagePath)
}

func (s FixedPaths) GetStoragePrefix(otype storage.ObjectType) (string, error) {
	switch otype {
	case storage.ObjectPathCheckpoints, storage.ObjectCheckpoint:
		return s.CheckpointsRoot, nil
	case storage.ObjectMassifData, storage.ObjectMassifStart, storage.ObjectPathMassifs:
		return s.MassifsRoot, nil
	default:
		return s.MassifsRoot, nil
	}
}

func (s FixedPaths) GetObjectIndex(storagePath string, otype storage.ObjectType) (uint32, error) {
	switch otype {
	case storage.ObjectCheckpoint:
		fallthrough
	case storage.ObjectMassifStart:
		fallthrough
	case storage.ObjectMassifData:
		return massifIndexFromPath(storagePath)
	default:
		return ^uint32(0), fmt.Errorf("unsupported object type")
	}
}

// GetStoragePath returns the storage path for a massif index and object type.
// If otype is Undefined, a massif path is returned
func (s FixedPaths) GetStoragePath(massifIndex uint32, otype storage.ObjectType) string {
	switch otype {
	case storage.ObjectPathMassifs:
		return s.MassifsRoot
	case storage.ObjectPathCheckpoints:
		return s.CheckpointsRoot
	case storage.ObjectCheckpoint:
		return fmt.Sprintf(
			"%s%s", s.CheckpointsRoot, fmt.Sprintf(V1MMRSignedTreeHeadBlobNameFmt, massifIndex),
		)
	case storage.ObjectMassifStart:
		fallthrough
	case storage.ObjectMassifData:
		fallthrough
	default:
		return fmt.Sprintf(
			"%s%s", s.MassifsRoot, fmt.Sprintf(V1MMRBlobNameFmt, massifIndex),
		)
	}
}
