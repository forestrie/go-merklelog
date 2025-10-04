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

func ParsePrefixedLogID(prefix string, storagePath string) LogID {

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
