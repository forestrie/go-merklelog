package massifs

import (
	"errors"

	"github.com/forestrie/go-merklelog/mmr"
	"github.com/forestrie/go-merklelog/urkle"
)

const (
	// These constants are used to derive the size of the mmrblob format sections described at
	// https://github.com/datatrails/epic-8120-scalable-proof-mechanisms/blob/main/mmr/forestrie-mmrblobs.md#massif-basic-file-format

	// ValueBytes defines the width of ALL entries in the log. This fixed width
	// makes it possible to compute mmr current sizes based on knowing only the
	// massif height and the number of bytes in the file.
	ValueBytes = 32
	// ReservedHeaderSlots reserves a place to put the urkle trie root, used for
	// data recovery and proofs of exclusion, and any related material. And it
	// gives us a little flex in the data format for the initial launch of
	// forestrie. It would be frustrating to need a data migration for want of a
	// few bytes.
	ReservedHeaderSlots = 7 // reserves n * ValueBytes at the front of the blob
	StartHeaderSize     = ValueBytes + ValueBytes*ReservedHeaderSlots
	StartHeaderEnd      = StartHeaderSize
	// MaxMMRHeight no single log can by taller than this, and matches the allowable bit size of an mmrIndex.
	// Note that the max height *index* is 63
	MaxMMRHeight          = 64
	IndexHeaderBytes      = 32
	LogEntryBytes         = 32
	EntryByteSizeLogBase2 = 5
	ValueBitSizeLogBase2  = 8
	ValueByteSizeLogBase2 = 5
)

var (
	ErrLogEntryToSmall = errors.New("to few bytes to represent a valid log entry")
	ErrLogValueToSmall = errors.New("to few bytes to represent a valid log value")
	ErrLogValueBadSize = errors.New("log value size invalid")
)

func IndexFromBlobSize(size int) uint64 {
	if size == 0 {
		return 0
	}
	return uint64(size>>EntryByteSizeLogBase2) - 1
}

// IndexedLogValue returns the value bytes from log data corresponding to entry
// index i. No range checks are performed, out of range will panic.  This
// function assumes log data is sliced to the appropriate section for i to make
// sense (be it a leaf index or an mmrIndex)
func IndexedLogValue(logData []byte, i uint64) []byte {
	return logData[i*LogEntryBytes : i*LogEntryBytes+ValueBytes]
}

// FixedHeaderEnd returns the index of the first byte after the fixed header
func FixedHeaderEnd() uint64 {
	return ValueBytes + ReservedHeaderSlots*ValueBytes
}

// TrieHeaderStart returns the first byte of the index header data.
//
// In v2, this 32B region is the BloomHeaderV1.
func TrieHeaderStart() uint64 {
	return FixedHeaderEnd()
}

// TrieHeaderEnd returns the end of the bytes reserved for the index header data.
func TrieHeaderEnd() uint64 {
	return TrieHeaderStart() + IndexHeaderBytes
}

// PeakStackStart returns the first byte of the massif ancestor peak stack data
func PeakStackStart(massifHeight uint8) uint64 {
	leafCount := urkle.LeafCountForMassifHeight(massifHeight)
	sz, err := indexDataBytesV2(leafCount)
	if err != nil {
		panic(err)
	}
	return TrieHeaderEnd() + sz
}

// PeakStackLen returns the number of items in the ancestor peak stack
func PeakStackLen(massifIndex uint64) uint64 {
	return mmr.LeafMinusSpurSum(massifIndex)
}

func PeakStackEnd(massifHeight uint8) uint64 {
	start := PeakStackStart(massifHeight)
	return start + MaxMMRHeight*ValueBytes
}

func MassifLogEntries(dataLen int, massifHeight uint8) (uint64, error) {
	stackEnd := PeakStackEnd(massifHeight)
	if uint64(dataLen) < stackEnd {
		return 0, ErrMassifDataLengthInvalid
	}
	mmrByteCount := uint64(dataLen) - stackEnd
	return mmrByteCount / ValueBytes, nil
}
