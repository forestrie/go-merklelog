package urkle

// LeafCountForMassifHeight returns the fixed leaf capacity N for a massif height (one-based).
//
// In `massifs`, massifHeight is the one-based height h, so leaf capacity is:
//   N = 2^(h-1)
func LeafCountForMassifHeight(massifHeight uint8) uint64 {
	if massifHeight == 0 {
		return 0
	}
	return uint64(1) << (massifHeight - 1)
}

// CheckMassifHeightFitsLeafOrdinalBytes ensures the massifHeight leaf capacity can be
// represented by a leafOrdinal encoded in ordinalBytes bytes.
//
// leafOrdinal ranges over [0..N-1], so we require:
//   N <= 2^(8*ordinalBytes)
func CheckMassifHeightFitsLeafOrdinalBytes(massifHeight uint8, ordinalBytes uint8) error {
	n := LeafCountForMassifHeight(massifHeight)

	bits := uint64(ordinalBytes) * 8
	var maxN uint64
	if bits >= 64 {
		maxN = ^uint64(0)
	} else {
		maxN = uint64(1) << bits
	}

	if n > maxN {
		return ErrLeafOrdinalDoesNotFit
	}
	return nil
}


