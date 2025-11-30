package massifs

/**
 * A Trie Entry is the companion data to an mmr entry.
 *
 * Its current format is:
 *
 * H( DOMAIN  || LOGID || APPID) + idtimestamp
 *
 * We hash the application data in order to stop data leakage.
 *
 * It is stored on the log in relation to the mmr entries as follows:
 *
 * |--------|------------------------------|----------------------------|
 * | header | trieEntry0 ---> trieEntryMax | mmrEntry1 ---> mmrEntryMax |
 * |--------|------------------------------|----------------------------|
 */

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (

	/**
	 * Each Trie Entry is the following:
	 *
	 * |----------|-------------|--------------|
	 * | Trie Key | Extra Bytes | ID Timestamp |
	 * |----------|-------------|--------------|
	 * | 32 bytes |  24 bytes   |    8 bytes   |
	 * |----------|-------------|--------------|
	 *
	 * Where Trie Value = Extra Bytes + ID Timestamp
	 */

	TrieEntryBytes            = 32 * 2 // 32 for trie key and 32 for trie value
	TrieKeyBytes              = 32
	TrieKeyEnd                = TrieKeyBytes
	TrieEntryIDTimestampStart = 32 + 24
	TrieEntrySnowflakeIDBytes = 8
	TrieEntryIDTimestampEnd   = TrieEntryIDTimestampStart + TrieEntrySnowflakeIDBytes
	TrieEntryExtraBytesStart  = 32
	TrieEntryExtraBytesSize   = 24
	TrieEntryExtraBytesEnd    = TrieEntryExtraBytesStart + TrieEntryExtraBytesSize
)

var ErrIndexEntryBadSize = errors.New("log index size invalid")

// TrieEntryOffset calculates the trie entry offset in bytes into an mmrblob,
//
//	for the trie entry at the given trie index.
//
// The blob format is described here
// https://github.com/datatrails/epic-8120-scalable-proof-mechanisms/blob/main/mmr/forestrie-mmrblobs.md#massif-basic-file-format
//
// In summary, the massif log looks something like this:
//
//	|------|------------------------------|----------|----------------------------|
//	|HEADER| trieEntry0 ---> trieEntryMax |peak stack| mmrEntry0 ---> mmrEntryMax |
//	|------|------------------------------|----------|----------------------------|
//
// Where the trie entries are pre-allocated to zero and start after the single
// fixed size HEADER entry. We can get the starting byte of the trie data
// log of a particular massif, by calling `massifContext.IndexStart()`.
//
// Each trie entry has the following format
//
//	+-----------------------------------+
//	| H( DOMAIN || LOGID || APPID )     | . trie key
//	+-----------------------------------+
//	|<reserved and zero>    |idtimestamp| . recovery information
//	+-----------------------------------+
//	|                         24 .. 31  |
//
// The idtimestamp is preserved in the clear so that we can always account for
// any log entry given only the original pre-image.
//
// The idtimestamps are unique and not included in information shared across
// logs. So storing them like this does not increase the information leakage of
// the public data in terms of log activity.
//
// The log id is included in the trieKey to ensure trieKeys across logs
// are not the same. This ensures that to recreate the hash a user must have
// all parts of the pre-image, including the app id.
//
// Whereas without the logID included in the hash, trieKeys across logs
// for shared events will be the same. We are using the logID as a log
// wide salt for the trie key hash.
//
// An mmr entry and its idtimestamp are committed atomically to the log. Once
// both exist, the mmr entry is verifiable. This is true *even if* the COMMIT
// message gets lost after updating the log. In principal, forestrie *creates*
// the idtimestamp so forestrie should always be able to reconcile it.
//
// Dropping the id isn't a problem for compliance and verifiability use cases,
// because in all those situations the verifier MUST present a verifiable
// pre-image which will include the id. And we only share on COMMIT, which means
// by definition the id got back to the customer.  In a recovery situation
// however, we may have records in the database for which the COMMIT message got
// lost in transit. In that case we would not be able to re-create the leaf from
// the database and so could not recover the log from just a database backup.
func TrieEntryOffset(indexStart uint64, leafIndex uint64) uint64 {
	trieEntryOffset := indexStart + (leafIndex)*TrieEntryBytes
	return trieEntryOffset
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
