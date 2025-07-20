package storage

import "errors"

var (
	ErrLogEmpty             = errors.New("the log is empty")
	ErrExistsOC             = errors.New("optimistic concurrency failure, subject already exists")
	ErrContentOC            = errors.New("optimistic concurrency failure, content to replace does not match expected content")
	ErrLogNotSelected       = errors.New("no log selected, please call SelectLog first")
	ErrNativeNotImplemented = errors.New("the provider does not implement access to its native implementation")
	ErrNotAvailable         = errors.New("object not available, please call Prime or Read first")
	ErrDoesNotExist         = errors.New("object does not exist")
	ErrOpConfigMissing = errors.New("required configuration missing for the selected operation")
)
