package massifs

import (
	"encoding/binary"
	"reflect"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTrieEntryOffset tests:
//
// 1. we get the correct offset for the trie entry at trie index 0
// 2. we get the correct offset for the trie entry at trie index 1
func TestTrieEntryOffset(t *testing.T) {
	type args struct {
		indexStart uint64
		leafIndex  uint64
	}
	tests := []struct {
		name     string
		args     args
		expected uint64
	}{
		{
			name: "first entry",
			args: args{
				indexStart: uint64(100),
				leafIndex:  uint64(0),
			},
			expected: 100,
		},
		{
			name: "second entry",
			args: args{
				indexStart: uint64(100),
				leafIndex:  uint64(1),
			},
			expected: 164,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := TrieEntryOffset(test.args.indexStart, test.args.leafIndex)

			assert.Equal(t, test.expected, actual)
		})
	}
}

// TestNewTrieKey tests:
//
// 1. we can create a trie key and its format is correct.
func TestNewTrieKey(t *testing.T) {
	type args struct {
		logID []byte
		appID []byte
	}
	tests := []struct {
		name     string
		args     args
		expected []byte
	}{
		// These tests simply ensure we are hashing things in the expected
		// order. To update them after changing that order, just run them,
		// capture the new hash and copy it into the test.
		{
			name: "typical datatrails event",
			args: args{
				logID: []byte("tenant/1de5793f-1421-45d8-999e-9513552f8c0b"),
				appID: []byte("assets/9eb98893-e0e3-4c21-99c2-0a88d7b2c2ea/events/c0cd94a9-3489-4957-baf9-cf75d478b53f"),
			},
			expected: []uint8{123, 35, 118, 210, 212, 254, 212, 242, 52, 254, 186, 214, 7, 135, 29, 32, 194, 28, 222, 28, 169, 234, 74, 175, 58, 4, 21, 140, 63, 83, 150, 79},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := NewTrieKey(0, test.args.logID, test.args.appID)

			assert.Equal(t, test.expected, actual)
		})
	}
}

// NewEmptyTrieEntry tests:
//
// 1. we can generate a new empty trie entry.
func TestNewEmptyTrieEntry(t *testing.T) {
	tests := []struct {
		name string
		want []byte
	}{
		{"test empty generated is correct", make([]byte, 64)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewEmptyTrieEntry(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewEmptyTrieEntry() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSetLogIndexEntry(t *testing.T) {
	expectTrieEntryBytes := 64

	// If this fails, then we are likely updating the index format and this test needs updating.
	require.Equal(t, expectTrieEntryBytes, TrieEntryBytes)

	b64clear := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	b64h0 := []byte{0, 0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0}
	b64h1 := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0}
	b64zero := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	b64one := []byte{1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	b64two := []byte{2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	b64three := []byte{3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}
	b64four := []byte{4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4}
	type args struct {
		logData     []byte
		indexStart  uint64
		leafIndex   uint64
		idTimestamp uint64
		extraBytes  []byte
		index       []byte
		before      []byte
		after       []byte
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "get trie index 1",
			args: args{
				logData:     slices.Concat(b64h0, b64h1, b64zero, b64one, b64two, b64three, b64four),
				indexStart:  uint64(expectTrieEntryBytes * 2),
				leafIndex:   1, // *trie* index NOT mmrIndex,
				idTimestamp: 0x0102030405060708,
				extraBytes:  []byte(`888888888888888888888888`), // maxiumum size of 24 bytes
				index:       b64one[:32],
				before:      b64zero[:32],
				after:       b64two[:32],
			},
		},
		{
			name: "get trie index 3",
			args: args{
				logData:     slices.Concat(b64h0, b64h1, b64zero, b64one, b64two, b64three, b64four),
				indexStart:  uint64(expectTrieEntryBytes * 2),
				leafIndex:   3, // *trie* index NOT mmrIndex
				idTimestamp: 0x0102030405060708,
				extraBytes:  []byte(`8888888888888888888888889999`), // overflow maxiumum size of 24 bytes (should truncate the 9's)
				index:       b64three[:32],
				before:      b64two[:32],
				after:       b64four[:32],
			},
		},
		{
			name: "get trie index 3, nil extra bytes",
			args: args{
				logData:     slices.Concat(b64h0, b64h1, b64zero, b64one, b64two, b64three, b64four),
				indexStart:  uint64(expectTrieEntryBytes * 2),
				leafIndex:   3, // *trie* index NOT mmrIndex
				idTimestamp: 0x0102030405060708,
				extraBytes:  nil,
				index:       b64three[:32],
				before:      b64two[:32],
				after:       b64four[:32],
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// First test that we get our expected pre-filled data
			got := GetTrieKey(tt.args.logData, tt.args.indexStart, tt.args.leafIndex)
			assert.Equal(t, got, tt.args.index)
			// Check that we can set it to zero without corrupting entries to either side
			if tt.args.before == nil && tt.args.after == nil {
				return
			}
			SetTrieEntry(tt.args.logData, tt.args.indexStart, tt.args.leafIndex, tt.args.idTimestamp, tt.args.extraBytes, b64clear)

			gotBefore := GetTrieKey(tt.args.logData, tt.args.indexStart, tt.args.leafIndex-1)
			assert.Equal(t, tt.args.before, gotBefore)
			gotAfter := GetTrieKey(tt.args.logData, tt.args.indexStart, tt.args.leafIndex+1)
			assert.Equal(t, tt.args.after, gotAfter)

			// check we get back the zeros we set

			got = GetTrieKey(tt.args.logData, tt.args.indexStart, tt.args.leafIndex)
			assert.Equal(t, b64clear[:32], got)

			gotID := GetIdtimestamp(tt.args.logData, tt.args.indexStart, tt.args.leafIndex)
			assert.Equal(t, tt.args.idTimestamp, binary.BigEndian.Uint64(gotID))

			// check the extra bytes
			gotBytes := GetExtraBytes(tt.args.logData, tt.args.indexStart, tt.args.leafIndex)
			assert.Equal(t, 24, len(gotBytes)) // make doubley sure we have filled the extra bytes and there is no overflow

			if tt.args.extraBytes != nil {
				assert.Equal(t, tt.args.extraBytes[0:24], gotBytes)
			}

			// Test equivalence with SetTrieEntryExtra when only one extraBytes slice is provided
			// Reset the data to original state
			copy(tt.args.logData, slices.Concat(b64h0, b64h1, b64zero, b64one, b64two, b64three, b64four))
			got = GetTrieKey(tt.args.logData, tt.args.indexStart, tt.args.leafIndex)
			assert.Equal(t, got, tt.args.index)

			// Use SetTrieEntryExtra with single extraBytes slice
			// Use massifHeight 3 (8 entries) to accommodate test indices up to 4
			massifHeight := uint8(3)
			if tt.args.extraBytes != nil {
				SetTrieEntryExtra(massifHeight, tt.args.logData, tt.args.indexStart, tt.args.leafIndex, tt.args.idTimestamp, b64clear, tt.args.extraBytes)
			} else {
				SetTrieEntryExtra(massifHeight, tt.args.logData, tt.args.indexStart, tt.args.leafIndex, tt.args.idTimestamp, b64clear)
			}

			// Verify results match SetTrieEntry
			gotBeforeExtra := GetTrieKey(tt.args.logData, tt.args.indexStart, tt.args.leafIndex-1)
			assert.Equal(t, tt.args.before, gotBeforeExtra)
			gotAfterExtra := GetTrieKey(tt.args.logData, tt.args.indexStart, tt.args.leafIndex+1)
			assert.Equal(t, tt.args.after, gotAfterExtra)

			gotExtra := GetTrieKey(tt.args.logData, tt.args.indexStart, tt.args.leafIndex)
			assert.Equal(t, b64clear[:32], gotExtra)

			gotIDExtra := GetIdtimestamp(tt.args.logData, tt.args.indexStart, tt.args.leafIndex)
			assert.Equal(t, tt.args.idTimestamp, binary.BigEndian.Uint64(gotIDExtra))

			gotBytesExtra := GetExtraBytes(tt.args.logData, tt.args.indexStart, tt.args.leafIndex)
			assert.Equal(t, 24, len(gotBytesExtra))

			if tt.args.extraBytes != nil {
				assert.Equal(t, tt.args.extraBytes[0:24], gotBytesExtra)
			}
		})
	}
}

func TestSetTrieEntryExtra(t *testing.T) {
	expectTrieEntryBytes := 64

	// If this fails, then we are likely updating the index format and this test needs updating.
	require.Equal(t, expectTrieEntryBytes, TrieEntryBytes)

	b64clear := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	b64h0 := []byte{0, 0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0}
	b64h1 := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0}
	b64zero := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	b64one := []byte{1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	b64two := []byte{2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	b64three := []byte{3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}
	b64four := []byte{4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4}

	// Create test data large enough to accommodate extended storage
	// With massifHeight 3, we have 8 entries (512 bytes) + extended storage (512 bytes) = 1024 bytes
	// indexStart is at 128, so we need at least 128 + 1024 = 1152 bytes
	// For entry at index 4 with extended bytes[2]: offset = 128 + 4*64 + 512 + 64 = 960, so we need at least 1024 bytes
	massifHeight := uint8(3)
	trieDataSize := TrieDataSize(massifHeight) // 8 * 64 = 512
	extendedStorageSize := trieDataSize        // Extended storage is same size as trie data
	totalTrieAreaSize := trieDataSize + extendedStorageSize
	indexStart := uint64(expectTrieEntryBytes * 2) // 128
	requiredSize := indexStart + totalTrieAreaSize // 128 + 1024 = 1152

	// Create base test data template
	baseDataTemplate := slices.Concat(b64h0, b64h1, b64zero, b64one, b64two, b64three, b64four)
	padSize := int(requiredSize) - len(baseDataTemplate)
	var pad []byte
	if padSize > 0 {
		pad = make([]byte, padSize)
	}

	// Test data for extended extra bytes
	extraBytes0 := make([]byte, 24)
	for i := range extraBytes0 {
		extraBytes0[i] = byte(0xAA + i)
	}
	extraBytes1 := make([]byte, 32)
	for i := range extraBytes1 {
		extraBytes1[i] = byte(0xBB + i)
	}
	extraBytes2 := make([]byte, 32)
	for i := range extraBytes2 {
		extraBytes2[i] = byte(0xCC + i)
	}
	extraBytes3 := make([]byte, 32) // This should be ignored
	for i := range extraBytes3 {
		extraBytes3[i] = byte(0xDD + i)
	}

	type args struct {
		logData     []byte
		indexStart  uint64
		leafIndex   uint64
		idTimestamp uint64
		trieKey     []byte
		extraBytes  [][]byte
	}
	tests := []struct {
		name           string
		args           args
		wantExtraBytes [][]byte // Expected extra bytes at each location
		verifyExtended bool     // Whether to verify extended locations
	}{
		{
			name: "zero extraBytes",
			args: args{
				logData:     slices.Concat(baseDataTemplate, pad),
				indexStart:  indexStart,
				leafIndex:   1,
				idTimestamp: 0x0102030405060708,
				trieKey:     b64clear[:32],
				extraBytes:  nil,
			},
			wantExtraBytes: nil,
			verifyExtended: false,
		},
		{
			name: "one extraBytes",
			args: args{
				logData:     slices.Concat(baseDataTemplate, pad),
				indexStart:  indexStart,
				leafIndex:   1,
				idTimestamp: 0x0102030405060708,
				trieKey:     b64clear[:32],
				extraBytes:  [][]byte{extraBytes0},
			},
			wantExtraBytes: [][]byte{extraBytes0},
			verifyExtended: false,
		},
		{
			name: "two extraBytes",
			args: args{
				logData:     slices.Concat(baseDataTemplate, pad),
				indexStart:  indexStart,
				leafIndex:   1, // Extended bytes written to extended storage area at trieEntryOffset + TrieDataSize
				idTimestamp: 0x0102030405060708,
				trieKey:     b64clear[:32],
				extraBytes:  [][]byte{extraBytes0, extraBytes1},
			},
			wantExtraBytes: [][]byte{extraBytes0, extraBytes1},
			verifyExtended: true,
		},
		{
			name: "three extraBytes",
			args: args{
				logData:     slices.Concat(baseDataTemplate, pad),
				indexStart:  indexStart,
				leafIndex:   1, // Extended bytes written to extended storage area at trieEntryOffset + TrieDataSize
				idTimestamp: 0x0102030405060708,
				trieKey:     b64clear[:32],
				extraBytes:  [][]byte{extraBytes0, extraBytes1, extraBytes2},
			},
			wantExtraBytes: [][]byte{extraBytes0, extraBytes1, extraBytes2},
			verifyExtended: true,
		},
		{
			name: "more than three extraBytes (should ignore extras)",
			args: args{
				logData:     slices.Concat(baseDataTemplate, pad),
				indexStart:  indexStart,
				leafIndex:   1, // Extended bytes written to extended storage area at trieEntryOffset + TrieDataSize
				idTimestamp: 0x0102030405060708,
				trieKey:     b64clear[:32],
				extraBytes:  [][]byte{extraBytes0, extraBytes1, extraBytes2, extraBytes3},
			},
			wantExtraBytes: [][]byte{extraBytes0, extraBytes1, extraBytes2}, // extraBytes3 should be ignored
			verifyExtended: true,
		},
		{
			name: "nil extraBytes[0] with extended bytes (skip standard field)",
			args: args{
				logData:     slices.Concat(baseDataTemplate, pad),
				indexStart:  indexStart,
				leafIndex:   1, // Extended bytes written to extended storage area at trieEntryOffset + TrieDataSize
				idTimestamp: 0x0102030405060708,
				trieKey:     b64clear[:32],
				extraBytes:  [][]byte{nil, extraBytes1, extraBytes2}, // nil for [0], write only extended
			},
			wantExtraBytes: [][]byte{nil, extraBytes1, extraBytes2}, // nil means don't write standard field
			verifyExtended: true,
		},
		{
			name: "trieIndex 0 with extended bytes (fixes bug where index 0 would overwrite entry)",
			args: args{
				logData:     slices.Concat(baseDataTemplate, pad),
				indexStart:  indexStart,
				leafIndex:   0, // Extended bytes written to extended storage area at trieEntryOffset + TrieDataSize
				idTimestamp: 0x0102030405060708,
				trieKey:     b64clear[:32],
				extraBytes:  [][]byte{extraBytes0, extraBytes1, extraBytes2},
			},
			wantExtraBytes: [][]byte{extraBytes0, extraBytes1, extraBytes2},
			verifyExtended: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh copy of the test data for each test to avoid cross-test contamination
			testData := make([]byte, len(tt.args.logData))
			copy(testData, tt.args.logData)

			// Determine expected initial key based on leafIndex
			var expectedInitialKey []byte
			if tt.args.leafIndex == 0 {
				expectedInitialKey = b64zero[:32]
			} else {
				expectedInitialKey = b64one[:32]
			}

			// Verify initial state
			got := GetTrieKey(testData, tt.args.indexStart, tt.args.leafIndex)
			assert.Equal(t, expectedInitialKey, got)

			// Capture original extra bytes if we're testing nil case
			var originalExtraBytes []byte
			if len(tt.wantExtraBytes) > 0 && tt.wantExtraBytes[0] == nil {
				originalExtraBytes = make([]byte, 24)
				copy(originalExtraBytes, GetExtraBytes(testData, tt.args.indexStart, tt.args.leafIndex))
			}

			// Call SetTrieEntryExtra
			SetTrieEntryExtra(massifHeight, testData, tt.args.indexStart, tt.args.leafIndex, tt.args.idTimestamp, tt.args.trieKey, tt.args.extraBytes...)

			// Verify trieKey at the main entry
			got = GetTrieKey(testData, tt.args.indexStart, tt.args.leafIndex)
			assert.Equal(t, tt.args.trieKey, got)

			// Verify idTimestamp at the main entry
			gotID := GetIdtimestamp(testData, tt.args.indexStart, tt.args.leafIndex)
			assert.Equal(t, tt.args.idTimestamp, binary.BigEndian.Uint64(gotID))

			// Verify standard extra bytes field at the main entry
			gotBytes := GetExtraBytes(testData, tt.args.indexStart, tt.args.leafIndex)
			assert.Equal(t, 24, len(gotBytes))
			if len(tt.wantExtraBytes) > 0 && tt.wantExtraBytes[0] != nil {
				assert.Equal(t, tt.wantExtraBytes[0][:24], gotBytes)
			} else if len(tt.wantExtraBytes) > 0 && tt.wantExtraBytes[0] == nil {
				// If extraBytes[0] is nil, the standard field should remain unchanged
				assert.Equal(t, originalExtraBytes, gotBytes)
			}

			// Verify extended extra bytes fields if applicable
			// Extended bytes are written to the extended storage area at trieEntryOffset + TrieDataSize
			if tt.verifyExtended && len(tt.wantExtraBytes) > 1 {
				trieEntryOffset := TrieEntryOffset(tt.args.indexStart, tt.args.leafIndex)
				trieEntryXOffset := trieEntryOffset + TrieDataSize(massifHeight)
				if tt.wantExtraBytes[1] != nil {
					gotExtended1 := testData[trieEntryXOffset : trieEntryXOffset+ValueBytes]
					assert.Equal(t, tt.wantExtraBytes[1][:32], gotExtended1)
				}

				if len(tt.wantExtraBytes) > 2 && tt.wantExtraBytes[2] != nil {
					gotExtended2 := testData[trieEntryXOffset+ValueBytes : trieEntryXOffset+ValueBytes*2]
					assert.Equal(t, tt.wantExtraBytes[2][:32], gotExtended2)
				}
			}

			// Verify adjacent entries are not corrupted
			// Extended bytes are in a separate storage area, so adjacent entries should be unchanged
			if tt.args.leafIndex > 0 {
				gotBefore := GetTrieKey(testData, tt.args.indexStart, tt.args.leafIndex-1)
				if tt.args.leafIndex-1 == 0 {
					assert.Equal(t, b64zero[:32], gotBefore)
				} else {
					assert.Equal(t, b64one[:32], gotBefore)
				}
			}

			// Check entry after - extended bytes are in separate storage, so this should be unchanged
			gotAfter := GetTrieKey(testData, tt.args.indexStart, tt.args.leafIndex+1)
			// Determine expected key based on leafIndex
			var expectedAfter []byte
			if tt.args.leafIndex == 0 {
				expectedAfter = b64one[:32] // Entry at index 1
			} else {
				expectedAfter = b64two[:32] // Entry at index 2
			}
			assert.Equal(t, expectedAfter, gotAfter)
		})
	}
}
