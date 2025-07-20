package storageschema

import "github.com/datatrails/go-datatrails-merklelog/massifs/storage"

type PrefixProvider interface {
	Prefix(lodID storage.LogID) string
}
