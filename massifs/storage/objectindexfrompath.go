package storage

import (
	"fmt"
	"strconv"
	"strings"
)

type ObjectIndexFromPathFunc func(storagePath string) (ObjectType, uint32, error)

func ObjectIndexFromPath(storagePath string) (ObjectType, uint32, error) {
	var err error
	// ensure it doesn't end with a slash
	storagePath = strings.TrimSuffix(storagePath, "/")
	i := strings.LastIndex(storagePath, "/")
	baseName := storagePath[i+1:]

	// Check for v2 path format
	if strings.HasPrefix(storagePath, V2MerklelogMassifsPrefix) || strings.HasPrefix(storagePath, V2MerklelogCheckpointsPrefix) {
		// V2 format uses base 10 integer indices (same as v1)
		otypes := []ObjectType{
			ObjectMassifData,
			ObjectCheckpoint,
		}

		for itype, suffix := range []string{
			V1MMRExtSep + V1MMRMassifExt,
			V1MMRExtSep + V1MMRSealSignedRootExt,
		} {
			if !strings.HasSuffix(baseName, suffix) {
				continue
			}
			// Parse base 10 integer index
			indexStr := baseName[:len(baseName)-len(suffix)]
			i, err := strconv.Atoi(indexStr)
			if err != nil {
				return ObjectUndefined, ^uint32(0), err
			}
			return otypes[itype], uint32(i), nil
		}
		return ObjectUndefined, ^uint32(0), fmt.Errorf("path %s has no recognizable object suffix", storagePath)
	}

	// V1 format uses decimal indices
	otypes := []ObjectType{
		ObjectMassifData,
		ObjectCheckpoint,
	}

	for itype, suffix := range []string{
		V1MMRExtSep + V1MMRMassifExt,
		V1MMRExtSep + V1MMRSealSignedRootExt,
	} {
		if !strings.HasSuffix(baseName, suffix) {
			continue
		}
		i, err = strconv.Atoi(baseName[:len(baseName)-len(suffix)])
		if err != nil {
			return ObjectUndefined, ^uint32(0), err
		}
		return otypes[itype], uint32(i), nil

	}
	return ObjectUndefined, ^uint32(0), fmt.Errorf("path %s has no recognizable object suffix", storagePath)
}
