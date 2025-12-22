package urkle

// KeyFieldView describes how to iterate keys inside a contiguous record array without copying.
//
// For this urkle format, keys are stored in the leaf table records:
//
//	record[0:8]   = key_be8
//	record[8:40]  = valueBytes[32]
//	record[40:64] = extra1[24]
//	record[64:96] = extra2[32]
//	record[96:128]= extra3[32]
type KeyFieldView struct {
	Data        []byte
	RecordBytes uint64
	KeyOffset   uint64
	KeyBytes    uint64
	Count       uint32 // number of filled records (typically nextLeaf)
}

// KeyData returns a contiguous slice of idtimestamps if the on-disk format stores keys
// contiguously with no per-record stride.
//
// For the current fixed-size leaf-table format, keys are strided (every 128 bytes),
// so this returns (nil, false).
func KeyData(_ IndexView, _ uint32) ([]byte, bool) {
	return nil, false
}

// KeyFields returns a descriptor for iterating over keys in the leaf table without copying.
func KeyFields(v IndexView, nextLeaf uint32) KeyFieldView {
	// Clamp nextLeaf to capacity defensively.
	cap32 := uint32(v.LeafCount)
	if nextLeaf > cap32 {
		nextLeaf = cap32
	}

	return KeyFieldView{
		Data:        v.LeafTable,
		RecordBytes: LeafRecordBytes,
		KeyOffset:   0,
		KeyBytes:    8,
		Count:       nextLeaf,
	}
}
