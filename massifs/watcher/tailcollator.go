package watcher

import (
	"errors"
	"math/rand"
	"slices"

	"github.com/datatrails/go-datatrails-merklelog/massifs/storage"
	"github.com/datatrails/go-datatrails-merklelog/massifs/storageschema"
)

// LogTail records the newest (highest numbered) massif path in a log It is used
// to represent both the most recent massif log blob, and the most recent massif
// seal blob
type LogTail struct {
	LogID  storage.LogID
	Path   string
	Number uint32
	OType  storage.ObjectType
	LastID string
}

// LogTailCollator is used to collate the most recently modified massif blob paths for all tenants in a given time horizon
type LogTailCollator struct {
	Massifs          map[string]*LogTail
	Seals            map[string]*LogTail
	Path2LogID       storageschema.LogIDFromPathFunc
	Path2ObjectIndex storageschema.ObjectIndexFromPathFunc
}

// NewLogTailCollator creates a log tail collator
func NewLogTailCollator(
	path2LogID storageschema.LogIDFromPathFunc,
	path2ObjectIndex storageschema.ObjectIndexFromPathFunc,
) LogTailCollator {
	return LogTailCollator{
		Massifs:          make(map[string]*LogTail),
		Seals:            make(map[string]*LogTail),
		Path2LogID:       path2LogID,
		Path2ObjectIndex: path2ObjectIndex,
	}
}

// sortMapOfLogTails returns a lexically sorted list of the keys to map of
// LogTails It's not a stable sort, keys that are in the right place to start
// with may move as a result of this call.
func sortMapOfLogTails(m map[string]*LogTail) []string {
	// The go lang community seems pretty divided on O(1)iterators, and I think this is still "the way"
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// shuffleMapOfLogTails returns the list of keys shuffled using rand.Shuffle
// This should be used to avoid odd biases due to fixed order treatment of tenants.
func shuffleMapOfLogTails(m map[string]*LogTail) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	rand.Shuffle(len(keys), func(i, j int) {
		keys[i], keys[j] = keys[j], keys[i]
	})
	return keys
}

// MassifLogs returns the keys of the massifs map specifically shuffled to
// avoid biasing service based on lexical order of tenant identities or go lang
// default key ordering
func (c LogTailCollator) MassifLogs() []string {
	return shuffleMapOfLogTails(c.Massifs)
}

// SortedMassifLogs returns the keys of the massifs map in sorted order
func (c LogTailCollator) SortedMassifLogs() []string {
	return sortMapOfLogTails(c.Massifs)
}

// SealedLogs returns the keys of the seals map specifically shuffled to
// avoid biasing service based on lexical order of tenant identities or go lang
// default key ordering
func (c LogTailCollator) SealedLogs() []string {
	return shuffleMapOfLogTails(c.Seals)
}

// SortedSealedLogs returns the keys of the massifs map in sorted order
func (c LogTailCollator) SortedSealedLogs() []string {
	return sortMapOfLogTails(c.Seals)
}

func (c LogTailCollator) SortedTails(otype storage.ObjectType) []*LogTail {

	var tails []*LogTail

	var m map[string]*LogTail
	switch otype {
	case storage.ObjectMassifData, storage.ObjectMassifStart:
		m = c.Massifs
	case storage.ObjectCheckpoint:
		m = c.Seals
	default:
		return nil
	}

	for _, logid := range sortMapOfLogTails(m) {
		tails = append(tails, m[string(logid)])
	}
	return tails
}

func (c LogTailCollator) Tail(logid storage.LogID, otype storage.ObjectType) *LogTail {
	var m map[string]*LogTail
	switch otype {
	case storage.ObjectMassifData, storage.ObjectMassifStart:
		m = c.Massifs
	case storage.ObjectCheckpoint:
		m = c.Seals
	default:
		return nil
	}
	return m[string(logid)]
}

// CollatePath considers the path of a massif or seal blob and replaces the tail if appropriate.
// The lastid should be provided by the caller if it is known, the empty string may be used if it is not known.
func (c *LogTailCollator) CollatePath(storagePath string, lastid string) error {
	otype, number, err := c.Path2ObjectIndex(storagePath)
	if err != nil {
		return err
	}

	// if it is missing, it will be the empty string that is set
	logID := c.Path2LogID(storagePath)
	if logID == nil {
		return nil // no log ID, nothing to do
	}

	if otype == storage.ObjectMassifData {
		if logID == nil {
			return errors.New("missing log ID")
		}
		cur, ok := c.Massifs[string(logID)]
		if !ok {
			lt := &LogTail{
				OType:  otype,
				LogID:  logID,
				Path:   storagePath,
				Number: number,
				LastID: lastid,
			}
			c.Massifs[string(logID)] = lt
			return nil
		}
		if number <= cur.Number {
			return nil
		}
		cur.Path = storagePath
		cur.Number = number
		cur.LastID = lastid
		return nil
	}

	if otype != storage.ObjectCheckpoint {
		return nil
	}

	cur, ok := c.Seals[string(logID)]
	if !ok {
		lt := &LogTail{
			OType:  otype,
			LogID:  logID,
			Path:   storagePath,
			Number: number,
			LastID: lastid,
		}
		c.Seals[string(logID)] = lt
		return nil
	}
	if number <= cur.Number {
		return nil
	}
	cur.Path = storagePath
	cur.Number = number
	cur.LastID = lastid
	return nil
}
