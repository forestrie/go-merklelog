package massifs

/**
 * A Trie Entry is the companion data to an mmr entry.
 *
 * Each entry has four logical fields:

 * |---------------|--------------|
 * |   Key Bytes   | 32 Bytes     |
 * |---------------|--------------|
 * | Extra Bytes 0 | 32 bytes     |
 * |---------------|--------------|
 * | Extra Bytes 1 | 32 bytes     |
 * |---------------|--------------|
 * | Extra Bytes 2 | 32 bytes     |
 * |---------------|--------------|
 *
 * The precise semantics of each field are application defined.
 *
 * The index data is stored on the log in relation to the mmr entries as follows:
 *
 * |--------|-------------------|----------------------------|
 * | header | Page0 | Page1     | mmrEntry1 ---> mmrEntryMax |
 * |--------|-------------------|----------------------------|
 *           <- 2 * Page Size ->
 *
 * Page Size = 2^heighIndex
 *
 * So for the default massifHeight of 14 that is 1 << 13
 *
 * KeyBytes and ExtraBytes0 are in the first page at offset:
 *
 *  2 * LeafIndex * ValueBytes
 *
 * ExtraBytes1 and ExtraBytes2 are in the second page at the same relative
 * location.
 *
*
* The original DataTrails blob format is described here
* https://github.com/datatrails/epic-8120-scalable-proof-mechanisms/blob/main/mmr/forestrie-mmrblobs.md#massif-basic-file-format
*
* In summary, the massif log looks something like this:
*
* |------|-------------------|------------ |----------|----------------------------|
* |HEADER| trieEntry0 -> max | UNUSED PAGE |peak stack| mmrEntry0 ---> mmrEntryMax |
* |------|-------------------|-------------|----------|----------------------------|
*
*  The datatrails trieKey format is
*
* +-----------------------------------+
* | H( DOMAIN || LOGID || APPID )     | . Key Bytes
* +-----------------------------------+
* |<reserved and zero>    |idtimestamp| . ExtraBytes 0 - recovery information
* +-----------------------------------+
* |                         24 .. 31  |
*/

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	TrieEntryBytes            = 32 * 2 // 32 for trie key and 32 for trie value
	TrieKeyBytes              = 32
	TrieKeyEnd                = TrieKeyBytes
	TrieEntryIDTimestampStart = 32 + 24
	TrieEntrySnowflakeIDBytes = 8
	TrieEntryIDTimestampEnd   = TrieEntryIDTimestampStart + TrieEntrySnowflakeIDBytes
	TrieEntryExtraBytesStart  = 32
	TrieEntryExtraBytesSize   = 24
	TrieEntryExtraBytesEnd    = TrieEntryExtraBytesStart + TrieEntryExtraBytesSize
	TrieEntryExtraSlots       = 3
	TrieEntryExtraBytesSizeV2 = 32
	TrieEntryExtraBytesEndV2  = TrieEntryExtraBytesStart + TrieEntryExtraBytesSizeV2
)

var (
	ErrIndexEntryBadSize  = errors.New("log index entry size invalid")
	ErrExtraSlotsOverflow = errors.New("the fixed alowance of extrabyte has been exceeded")
	ErrExtraBytesToLarge  = errors.New("the fixed slot size for an extrabytes has been exceeded")
)

// TrieEntryOffset calculates the byte offset for a trie entry in an mmrblob
// based on the index start and the leaf index. Each trie entry is a fixed size
// of TrieEntryBytes, so the offset is calculated by multiplying the leaf index
// by the entry size and adding the index start.
func TrieEntryOffset(indexStart uint64, leafIndex uint64) uint64 {
	trieEntryOffset := indexStart + (leafIndex)*TrieEntryBytes
	return trieEntryOffset
}

// TrieEntryOffset calculates the byte offset for a trie entry in an mmrblob
// based on the index start and the leaf index. Each trie entry is a fixed size
// of TrieEntryBytes, so the offset is calculated by multiplying the leaf index
// by the entry size and adding the index start.
func TrieEntryOffset(indexStart uint64, leafIndex uint64) uint64 {
	trieEntryOffset := indexStart + (leafIndex)*TrieEntryBytes
	return trieEntryOffset
}

// CheckIndexData validates the input data for a trie index entry
//
// It performs the following checks:
// 1. Ensures the trieKey is exactly TrieKeyBytes long
// 2. Checks that the number of extraBytes does not exceed TrieEntryExtraSlots
// 3. Verifies that each extraBytes slice does not exceed TrieKeyBytes in length
//
// Returns an error if any of these validations fail, otherwise returns nil
func CheckIndexData(trieKey []byte, extraBytes ...[]byte) error {
	if len(trieKey) != TrieKeyBytes {
		return fmt.Errorf(
			"%w: triekey must be %d bytes not %d",
			ErrIndexEntryBadSize, TrieKeyBytes, len(trieKey))
	}

	if len(extraBytes) > TrieEntryExtraSlots {
		return ErrExtraSlotsOverflow
	}
	for i := range extraBytes {
		if len(extraBytes[i]) > TrieKeyBytes {
			return ErrExtraBytesToLarge
		}
	}
	return nil
}

func checkWriteRange(buf []byte, start, end uint64) error {
	if start > end {
		return fmt.Errorf("%w: invalid range %d-%d", ErrIndexEntryBadSize, start, end)
	}
	if end > uint64(len(buf)) {
		return fmt.Errorf(
			"%w: write exceeds buffer: want end=%d, len=%d",
			ErrIndexEntryBadSize, end, len(buf))
	}
	return nil
}

// SetIndexFields stores the trieKey and extraBytes in the predefined fields of the trie index
//
// This method writes data to fixed-size fields in the trie entry format, with the following constraints:
//
// - The keyBytes must be exactly 32 bytes long
// - Up to 3 extraBytes slices can be provided (corresponding to the reserved extra space)
// - Each extraBytes slice is limited to 32 bytes
//
// The extraBytes are stored in specific locations:
//   - extraBytes[0]: 32 bytes immediately after the trieKey (standard location)
//   - extraBytes[1]: 32 bytes in the first field in the extended storage page
//   - extraBytes[2]: 32 bytes in the second field in the extended storage page
//
// Nil extraBytes entries are allowed, which permits skipping specific fields.
//
// NOTE: trieIndex is equivalent to leafIndex, as trie entries are only added for leaf nodes.
//
// Parameters:
//   - trieData: The byte slice where the trie entry will be written
//   - massifHeight: Height of the massif, used to calculate extended storage offset
//   - indexStart: Starting byte offset of the index
//   - trieIndex: Index of the trie entry (leaf index)
//   - keyBytes: 32-byte key to be stored
//   - extraBytes: Optional additional bytes to store in extra slots
//
// Returns an error if:
//   - The keyBytes is not exactly 32 bytes
//   - More than 3 extraBytes slices are provided
//   - Any extraBytes slice exceeds 32 bytes
//   - Writing would exceed the buffer's bounds
func SetIndexFields(
	trieData []byte,
	massifHeight uint8,
	indexStart uint64, trieIndex uint64,
	keyBytes []byte, extraBytes ...[]byte,
) error {
	if err := CheckIndexData(keyBytes, extraBytes...); err != nil {
		return err
	}

	trieEntryOffset := TrieEntryOffset(indexStart, trieIndex)
	keyStart := trieEntryOffset
	keyEnd := trieEntryOffset + TrieKeyEnd
	if err := checkWriteRange(trieData, keyStart, keyEnd); err != nil {
		return err
	}
	copy(trieData[keyStart:keyEnd], keyBytes)

	if len(extraBytes) == 0 {
		return nil
	}

	// Note that we allow extraBytes entries to be nil so that the caller can
	// skip fields.

	// First extra bytes field (standard location)
	if extraBytes[0] != nil {
		extraBytesStart := trieEntryOffset + TrieEntryExtraBytesStart
		extraBytesEnd := trieEntryOffset + TrieEntryExtraBytesEndV2
		if err := checkWriteRange(trieData, extraBytesStart, extraBytesEnd); err != nil {
			return err
		}
		clear(trieData[extraBytesStart:extraBytesEnd])
		copy(trieData[extraBytesStart:extraBytesEnd], extraBytes[0])
	}

	if len(extraBytes) == 1 {
		return nil
	}

	// The extended storage area starts after all trie entries, so we add TrieDataSize
	// to the entry's offset to get the corresponding position in extended storage.
	trieEntryXOffset := trieEntryOffset + TrieDataSize(massifHeight)

	if extraBytes[1] != nil {
		slot1Start := trieEntryXOffset
		slot1End := trieEntryXOffset + ValueBytes
		if err := checkWriteRange(trieData, slot1Start, slot1End); err != nil {
			return err
		}
		clear(trieData[slot1Start:slot1End])
		copy(trieData[slot1Start:slot1End], extraBytes[1])
	}

	if len(extraBytes) == 2 {
		return nil
	}

	if extraBytes[2] != nil {
		slot2Start := trieEntryXOffset + ValueBytes
		slot2End := trieEntryXOffset + ValueBytes*2
		if err := checkWriteRange(trieData, slot2Start, slot2End); err != nil {
			return err
		}
		clear(trieData[slot2Start:slot2End])
		copy(trieData[slot2Start:slot2End], extraBytes[2])
	}

	return nil
}

// GetTrieEntry returns the trie entry corresponding to the given trie index,
//
//	from the given trie data.
//
// NOTE: trieIndex is equivilent to leafIndex.
func GetTrieEntry(trieData []byte, indexStart uint64, trieIndex uint64) []byte {
	trieEntryOffset := TrieEntryOffset(indexStart, trieIndex)
	return trieData[trieEntryOffset : trieEntryOffset+TrieEntryBytes]
}

// GetTrieKey returns the trieKey corresponding to the given trie index,
//
//	from the given trie data.
//
// NOTE: No range checks are performed, out of range will panic
//
// NOTE: trieIndex is equivilent to leafIndex.
func GetTrieKey(trieData []byte, indexStart uint64, trieIndex uint64) []byte {
	trieEntryOffset := TrieEntryOffset(indexStart, trieIndex)
	return trieData[trieEntryOffset : trieEntryOffset+TrieKeyEnd]
}

// GetIdtimestamp returns the idtimestamp corresponding to the given trie index,
//
//	from the given trie data.
//
// NOTE: trieIndex is equivilent to leafIndex.
func GetIdtimestamp(trieData []byte, indexStart uint64, trieIndex uint64) []byte {
	trieEntryOffset := TrieEntryOffset(indexStart, trieIndex)
	idStart := trieEntryOffset + TrieEntryIDTimestampStart
	idEnd := trieEntryOffset + TrieEntryIDTimestampEnd

	return trieData[idStart:idEnd]
}

// GetExtraBytes returns the extra bytes corresponding to the given trie index,
// from the given trie data.
//
// extraBytes are part of the trie value, where trieValue = extraBytes + idtimestamp
//
// NOTE: trieIndex is equivilent to leafIndex.
func GetExtraBytes(trieData []byte, indexStart uint64, trieIndex uint64) []byte {
	trieEntryOffset := TrieEntryOffset(indexStart, trieIndex)
	extraBytesStart := trieEntryOffset + TrieEntryExtraBytesStart
	extraBytesEnd := trieEntryOffset + TrieEntryExtraBytesEnd

	return trieData[extraBytesStart:extraBytesEnd]
}

// SetTrieEntry stores the trie Entry (trieKey + idTimestamp) in the given trie data at the given
//
//	trie index.
//
// NOTE: trieIndex is equivilent to leafIndex. This is because trie entries are only added
//
//	for leaves.
func SetTrieEntry(trieData []byte, indexStart uint64, trieIndex uint64,
	idTimestamp uint64, extraBytes []byte, trieKey []byte,
) {
	trieEntryOffset := TrieEntryOffset(indexStart, trieIndex)
	copy(trieData[trieEntryOffset:trieEntryOffset+TrieKeyEnd], trieKey)

	// extra bytes
	if extraBytes != nil {
		extraBytesStart := trieEntryOffset + TrieEntryExtraBytesStart
		extraBytesEnd := trieEntryOffset + TrieEntryExtraBytesEnd
		copy(trieData[extraBytesStart:extraBytesEnd], extraBytes)
	}

	// idtimestamp
	idTimestampStart := trieEntryOffset + TrieEntryIDTimestampStart
	idTimestampEnd := trieEntryOffset + TrieEntryIDTimestampEnd
	binary.BigEndian.PutUint64(trieData[idTimestampStart:idTimestampEnd], idTimestamp)
}

// SetTrieEntryExtra stores the trie Entry (trieKey + idTimestamp) in the given trie data at the given
//
//	trie index, with support for extended extra bytes storage.
//
// The extraBytes parameter is variadic and may contain at most 3 elements. This limit corresponds
// to the extra space reserved in the index. The original implementation in TrieDataEnd (see
// logformat.go:93-99) was an accidental bug that allocated double the needed space, but this is now
// part of the formal format specification.
//
// Handling of extraBytes:
//   - The first 24 bytes of extraBytes[0] (if provided) are written to the standard extra bytes field
//     of the trie entry (TrieEntryExtraBytesStart).
//   - If extraBytes[1] is provided, 32 bytes are written starting at trieEntryXOffset, where
//     trieEntryXOffset = trieEntryOffset + TrieDataSize(massifHeight). This places extended bytes
//     in the extended storage area that corresponds to the same relative position as the entry.
//   - If extraBytes[2] is provided, 32 bytes are written starting at trieEntryXOffset + ValueBytes.
//   - Any additional extraBytes elements beyond the third are silently ignored.
//
// NOTE: trieIndex is equivalent to leafIndex. This is because trie entries are only added for leaves.
func SetTrieEntryExtra(massifHeight uint8, trieData []byte, indexStart uint64, trieIndex uint64,
	idTimestamp uint64, trieKey []byte, extraBytes ...[]byte,
) {
	trieEntryOffset := TrieEntryOffset(indexStart, trieIndex)
	copy(trieData[trieEntryOffset:trieEntryOffset+TrieKeyEnd], trieKey)

	// First extra bytes field (standard location)
	if len(extraBytes) > 0 && extraBytes[0] != nil {
		extraBytesStart := trieEntryOffset + TrieEntryExtraBytesStart
		extraBytesEnd := trieEntryOffset + TrieEntryExtraBytesEnd
		copy(trieData[extraBytesStart:extraBytesEnd], extraBytes[0])
	}

	// idtimestamp
	idTimestampStart := trieEntryOffset + TrieEntryIDTimestampStart
	idTimestampEnd := trieEntryOffset + TrieEntryIDTimestampEnd
	binary.BigEndian.PutUint64(trieData[idTimestampStart:idTimestampEnd], idTimestamp)

	// Extended extra bytes fields (if provided)
	if len(extraBytes) > 1 {
		// Place extended bytes in the extended storage area at the same relative position.
		// The extended storage area starts after all trie entries, so we add TrieDataSize
		// to the entry's offset to get the corresponding position in extended storage.
		trieEntryXOffset := trieEntryOffset + TrieDataSize(massifHeight)
		if extraBytes[1] != nil {
			copy(trieData[trieEntryXOffset:trieEntryXOffset+ValueBytes], extraBytes[1])
		}

		if len(extraBytes) > 2 && extraBytes[2] != nil {
			copy(trieData[trieEntryXOffset+ValueBytes:trieEntryXOffset+ValueBytes*2], extraBytes[2])
		}
	}
}

// NewTrieKey creates the trie key value.
//
// The trie key can then be used to compose the trie entry,
// (trieKey + idTimestamp) that corresponds to an mmr entry.
//
// To avoid correlation attacks where the
// event identifying information appears on multiple logs, we hash the provided
// values to produce the final key. The returned value is a 32 byte SHA 256
// hash.  H( DOMAIN || LOGID || APPID )
func NewTrieKey(
	domain KeyType, logID []byte, appID []byte,
) []byte {
	h := sha256.New()

	h.Write([]byte{uint8(domain)})

	h.Write(logID)

	// sha256.Write does not error
	_, _ = h.Write(appID)

	return h.Sum(nil)
}

// NewEmptyTrieEntry is a convenience method that
// initializes the trie entry in the bytes representation to its zero value.
func NewEmptyTrieEntry() []byte {
	return make([]byte, TrieEntryBytes)
}
