package watcher

import "github.com/datatrails/go-datatrails-merklelog/massifs/storage"

// LogMassif identifies a combination of log and massif Typically it is
// used to convey that the massif is the most recently changed for that log
type LogMassif struct {
	Massif int    `json:"massifindex"`
	LogID  string `json:"logid"`
}

// LogActivity represents the per log output of the watch command
type LogActivity struct {
	// Massif is the massif index of the most recently appended massif
	Massif int `json:"massifindex"`
	// LogID is the identity of the most recently changed log
	// Note that encoding/json encodes the bytes as base64
	LogID storage.LogID `json:"logid"`

	// IDCommitted is the idtimestamp for the most recent entry observed in the log
	IDCommitted string `json:"idcommitted"`
	// IDConfirmed is the idtimestamp for the most recent entry to be sealed.
	IDConfirmed  string `json:"idconfirmed"`
	LastModified string `json:"lastmodified"`
	// MassifURL is the remote path to the most recently changed massif
	MassifURL string `json:"massif"`
	// CheckpointURL is the remote path to the most recently changed checkpoint
	CheckpointURL string `json:"checkpoint"`
}
