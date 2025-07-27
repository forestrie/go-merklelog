package storageschema

import "github.com/datatrails/go-datatrails-merklelog/massifs/storage"

type LogIDFromPathFunc func(storagePath string) storage.LogID
