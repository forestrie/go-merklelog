package bloom

import "encoding/binary"

func readU32BE(b []byte) uint32     { return binary.BigEndian.Uint32(b) }
func readU64BE(b []byte) uint64     { return binary.BigEndian.Uint64(b) }
func writeU32BE(b []byte, v uint32) { binary.BigEndian.PutUint32(b, v) }

