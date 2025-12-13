package massifs

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testBytes(seed byte, n int) []byte {
	b := make([]byte, n)
	for i := range n {
		b[i] = seed + byte(i)
	}
	return b
}

func valueField(trieData []byte, indexStart, trieIndex uint64) []byte {
	off := TrieEntryOffset(indexStart, trieIndex)
	start := off + TrieEntryExtraBytesStart
	end := off + TrieEntryExtraBytesEndV2
	return trieData[start:end]
}

func extendedField(trieData []byte, massifHeight uint8, indexStart, trieIndex uint64, slot uint64) []byte {
	off := TrieEntryOffset(indexStart, trieIndex)
	xoff := off + TrieDataSize(massifHeight)
	start := xoff + slot*ValueBytes
	end := start + ValueBytes
	return trieData[start:end]
}

func makeTrieDataTemplate(t *testing.T, massifHeight uint8, indexStart uint64) []byte {
	t.Helper()

	leafCount := uint64(1) << massifHeight
	trieAreaSize := TrieDataSize(massifHeight)
	wantLen := indexStart + trieAreaSize*2

	buf := make([]byte, wantLen)

	for i := range leafCount {
		off := TrieEntryOffset(indexStart, i)

		// key
		copy(buf[off:off+TrieKeyBytes], testBytes(byte(0x10+i), TrieKeyBytes))

		// value field (32 bytes)
		fill := bytes.Repeat([]byte{byte(0xE0 + i)}, TrieEntryExtraBytesSizeV2)
		copy(buf[off+TrieEntryExtraBytesStart:off+TrieEntryExtraBytesEndV2], fill)

		// extended slots
		xoff := off + trieAreaSize
		copy(buf[xoff:xoff+ValueBytes], bytes.Repeat([]byte{byte(0xA0 + i)}, ValueBytes))
		copy(buf[xoff+ValueBytes:xoff+ValueBytes*2], bytes.Repeat([]byte{byte(0xB0 + i)}, ValueBytes))
	}

	return buf
}

func TestSetIndexFields(t *testing.T) {
	indexStart := uint64(128)

	massifHeight := uint8(3) // 8 entries
	base := makeTrieDataTemplate(t, massifHeight, indexStart)

	trieIndex := uint64(3)
	origKeyBefore := bytes.Clone(GetTrieKey(base, indexStart, trieIndex-1))
	origKeyAt := bytes.Clone(GetTrieKey(base, indexStart, trieIndex))
	origKeyAfter := bytes.Clone(GetTrieKey(base, indexStart, trieIndex+1))
	origValueAt := bytes.Clone(valueField(base, indexStart, trieIndex))
	origExt1At := bytes.Clone(extendedField(base, massifHeight, indexStart, trieIndex, 0))
	origExt2At := bytes.Clone(extendedField(base, massifHeight, indexStart, trieIndex, 1))

	t.Run("key only does not mutate value or extended fields", func(t *testing.T) {
		data := bytes.Clone(base)
		newKey := testBytes(0x55, TrieKeyBytes)

		err := SetIndexFields(data, massifHeight, indexStart, trieIndex, newKey)
		require.NoError(t, err)

		assert.Equal(t, newKey, GetTrieKey(data, indexStart, trieIndex))
		assert.Equal(t, origValueAt, valueField(data, indexStart, trieIndex))
		assert.Equal(t, origExt1At, extendedField(data, massifHeight, indexStart, trieIndex, 0))
		assert.Equal(t, origExt2At, extendedField(data, massifHeight, indexStart, trieIndex, 1))

		// adjacent entries untouched
		assert.Equal(t, origKeyBefore, GetTrieKey(data, indexStart, trieIndex-1))
		assert.Equal(t, origKeyAfter, GetTrieKey(data, indexStart, trieIndex+1))
	})

	t.Run("extraBytes[0] full 32 overwrites entire value field", func(t *testing.T) {
		data := bytes.Clone(base)
		newKey := testBytes(0x56, TrieKeyBytes)
		extra0 := testBytes(0x01, TrieEntryExtraBytesSizeV2)

		err := SetIndexFields(data, massifHeight, indexStart, trieIndex, newKey, extra0)
		require.NoError(t, err)

		assert.Equal(t, newKey, GetTrieKey(data, indexStart, trieIndex))
		assert.Equal(t, extra0, valueField(data, indexStart, trieIndex))
	})

	t.Run("extraBytes[0] short is zero padded (cleared then copied)", func(t *testing.T) {
		data := bytes.Clone(base)
		newKey := testBytes(0x57, TrieKeyBytes)
		extra0 := testBytes(0x02, 24)

		err := SetIndexFields(data, massifHeight, indexStart, trieIndex, newKey, extra0)
		require.NoError(t, err)

		want := make([]byte, TrieEntryExtraBytesSizeV2)
		copy(want, extra0)
		assert.Equal(t, want, valueField(data, indexStart, trieIndex))
	})

	t.Run("nil extraBytes[0] skips value field while writing extended slot 1", func(t *testing.T) {
		data := bytes.Clone(base)
		newKey := testBytes(0x58, TrieKeyBytes)
		extra1 := testBytes(0x03, 10)

		err := SetIndexFields(data, massifHeight, indexStart, trieIndex, newKey, nil, extra1)
		require.NoError(t, err)

		assert.Equal(t, newKey, GetTrieKey(data, indexStart, trieIndex))
		assert.Equal(t, origValueAt, valueField(data, indexStart, trieIndex))

		want1 := make([]byte, ValueBytes)
		copy(want1, extra1)
		assert.Equal(t, want1, extendedField(data, massifHeight, indexStart, trieIndex, 0))
		assert.Equal(t, origExt2At, extendedField(data, massifHeight, indexStart, trieIndex, 1))
	})

	t.Run("extraBytes[1] and extraBytes[2] write both extended slots", func(t *testing.T) {
		data := bytes.Clone(base)
		newKey := testBytes(0x59, TrieKeyBytes)
		extra1 := testBytes(0x04, ValueBytes)
		extra2 := testBytes(0x05, ValueBytes)

		err := SetIndexFields(data, massifHeight, indexStart, trieIndex, newKey, nil, extra1, extra2)
		require.NoError(t, err)

		assert.Equal(t, newKey, GetTrieKey(data, indexStart, trieIndex))
		assert.Equal(t, origValueAt, valueField(data, indexStart, trieIndex))
		assert.Equal(t, extra1, extendedField(data, massifHeight, indexStart, trieIndex, 0))
		assert.Equal(t, extra2, extendedField(data, massifHeight, indexStart, trieIndex, 1))
	})

	t.Run("invalid key size errors", func(t *testing.T) {
		data := bytes.Clone(base)
		err := SetIndexFields(data, massifHeight, indexStart, trieIndex, []byte{1, 2, 3})
		require.ErrorIs(t, err, ErrIndexEntryBadSize)
	})

	t.Run("too many extraBytes errors", func(t *testing.T) {
		data := bytes.Clone(base)
		newKey := testBytes(0x5A, TrieKeyBytes)
		err := SetIndexFields(
			data, massifHeight, indexStart, trieIndex, newKey,
			[]byte{1}, []byte{2}, []byte{3}, []byte{4},
		)
		require.ErrorIs(t, err, ErrExtraSlotsOverflow)
	})

	t.Run("extraBytes element too large errors", func(t *testing.T) {
		data := bytes.Clone(base)
		newKey := testBytes(0x5B, TrieKeyBytes)
		extra0 := make([]byte, TrieKeyBytes+1)
		err := SetIndexFields(data, massifHeight, indexStart, trieIndex, newKey, extra0)
		require.ErrorIs(t, err, ErrExtraBytesToLarge)
	})

	t.Run("buffer too small for base entry returns error (no panic)", func(t *testing.T) {
		newKey := testBytes(0x5C, TrieKeyBytes)
		// keyEnd = indexStart + trieIndex*TrieEntryBytes + TrieKeyEnd
		keyEnd := TrieEntryOffset(indexStart, trieIndex) + TrieKeyEnd
		data := make([]byte, keyEnd-1) // 1 byte too short

		err := SetIndexFields(data, massifHeight, indexStart, trieIndex, newKey)
		require.ErrorIs(t, err, ErrIndexEntryBadSize)
	})

	t.Run("buffer too small for extended area returns error (no panic)", func(t *testing.T) {
		newKey := testBytes(0x5D, TrieKeyBytes)
		extra1 := testBytes(0x06, ValueBytes)

		// allocate enough for the base entry write, but not enough for extended slot 1.
		trieEntryOffset := TrieEntryOffset(indexStart, trieIndex)
		baseNeed := trieEntryOffset + TrieEntryExtraBytesEndV2
		data := make([]byte, baseNeed)

		err := SetIndexFields(data, massifHeight, indexStart, trieIndex, newKey, nil, extra1)
		require.ErrorIs(t, err, ErrIndexEntryBadSize)
	})

	// sanity check: massifHeight=0 (single entry) still computes offsets correctly
	t.Run("massifHeight 0 supports writing extended slots for trieIndex 0", func(t *testing.T) {
		h := uint8(0)
		is := uint64(0)
		idx := uint64(0)
		data := makeTrieDataTemplate(t, h, is)

		newKey := testBytes(0x60, TrieKeyBytes)
		extra1 := testBytes(0x07, ValueBytes)
		extra2 := testBytes(0x08, ValueBytes)

		err := SetIndexFields(data, h, is, idx, newKey, nil, extra1, extra2)
		require.NoError(t, err)

		assert.Equal(t, newKey, GetTrieKey(data, is, idx))
		assert.Equal(t, extra1, extendedField(data, h, is, idx, 0))
		assert.Equal(t, extra2, extendedField(data, h, is, idx, 1))
	})

	// ensure we didn't mutate the baseline template above
	require.Equal(t, origKeyAt, GetTrieKey(base, indexStart, trieIndex))
}
