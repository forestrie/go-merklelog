package urkle

import (
	"encoding/binary"
	"hash"
)

// HashWriteUint64 writes a uint64 to a hasher in big-endian layout.
func HashWriteUint64(hasher hash.Hash, value uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], value)
	_, _ = hasher.Write(b[:])
}

// HashWriteUint32 writes a uint32 to a hasher in big-endian layout.
func HashWriteUint32(hasher hash.Hash, value uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], value)
	_, _ = hasher.Write(b[:])
}

func readU32BE(b []byte) uint32 { return binary.BigEndian.Uint32(b) }
func readU64BE(b []byte) uint64 { return binary.BigEndian.Uint64(b) }

func writeU32BE(dst []byte, v uint32) { binary.BigEndian.PutUint32(dst, v) }
func writeU64BE(dst []byte, v uint64) { binary.BigEndian.PutUint64(dst, v) }


