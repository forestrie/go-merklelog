package storage

import (
	"strings"

	"github.com/google/uuid"
)

const (
	// LenUUIDString is the length of the UUID string representation, per
	// https://www.rfc-editor.org/rfc/rfc9562.html#name-uuid-format
	LenUUIDString = 36
)

// Where the log id is encoded in the storage path as a uuid with a well known prefix path component.
// Datatrails uses the 'tenant/' prefix to identify the log id in the storage path.
// V2 paths use the format: v2/merklelog/{massifs|checkpoints}/{height}/{uuid}/...

func ParsePrefixedLogID(prefix string, storagePath string) LogID {
	// Check for v2 path format first
	if strings.HasPrefix(storagePath, V2MerklelogMassifsPrefix) || strings.HasPrefix(storagePath, V2MerklelogCheckpointsPrefix) {
		// V2 format: v2/merklelog/{massifs|checkpoints}/{height}/{uuid}/...
		// Split path and extract UUID from 4th component (index 4)
		parts := strings.Split(storagePath, "/")
		if len(parts) >= 5 {
			// parts[0] = "v2"
			// parts[1] = "merklelog"
			// parts[2] = "massifs" or "checkpoints"
			// parts[3] = height
			// parts[4] = uuid
			uuidStr := parts[4]
			logID, err := uuid.Parse(uuidStr)
			if err != nil {
				return nil
			}
			return LogID(logID[:])
		}
		return nil
	}

	// V1 format: look for prefix like "tenant/"
	lenprefix := len(prefix)

	var i, j int
	i = strings.Index(storagePath, prefix)
	if i == -1 {
		return nil
	}

	// Allow the uuid to be followed by a slash or end of string.
	j = strings.Index(storagePath[i+lenprefix:], "/")
	if j == -1 {
		j = LenUUIDString
	}
	uuidStr := storagePath[i+lenprefix : i+lenprefix+j]
	logID, err := uuid.Parse(uuidStr)
	if err != nil {
		return nil
	}
	return LogID(logID[:])
}
