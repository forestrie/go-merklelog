package urkle

// bitAt returns the bit at index i where i=0 is the MSB (bit 63).
func bitAt(x uint64, i uint8) uint8 {
	shift := 63 - i
	return uint8((x >> shift) & 1)
}
