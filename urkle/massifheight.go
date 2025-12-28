package urkle

import "fmt"

// LeafCountForMassifHeight returns the fixed leaf capacity N for a massif
// height (one-based).
//
// In `massifs`, massifHeight is the one-based height h, so leaf capacity is:
//
//	N = 2^(h-1)
//
// NOTE: The underlying MMR maths permits heights up to a height index of 63
// (see massifs.MaxMMRHeight). However, the v2 Urkle index layout encodes
// leaf ordinals and leaf counts using 32-bit fields (LeafOrdinalBytes == 4
// and uint32-backed counters), so the practical leaf capacity per massif is
// capped at 2^32-1. Callers should use CheckMassifHeight or CheckLeafCount to
// enforce this bound when wiring massifHeight into an index format.
func LeafCountForMassifHeight(massifHeight uint8) uint64 {
	if massifHeight == 0 {
		return 0
	}
	return uint64(1) << (massifHeight - 1)
}

// CheckMassifHeight ensures the leaf capacity implied by massifHeight fits the
// on-disk leafOrdinal / leafCount encodings.
//
// Currently this is equivalent to applying CheckLeafCount to
// LeafCountForMassifHeight(massifHeight), so the effective bound is
// LeafCountForMassifHeight(massifHeight) <= 2^32-1 when LeafOrdinalBytes == 4.
func CheckMassifHeight(massifHeight uint8) error {
	n := LeafCountForMassifHeight(massifHeight)
	return CheckLeafCount(n)
}

// CheckMassifHeightFitsLeafOrdinalBytes ensures the massifHeight leaf
// capacity can be represented by a leafOrdinal encoded in ordinalBytes bytes.
//
// leafOrdinal ranges over [0..N-1], so we require:
//
//	N <= 2^(8*ordinalBytes)
//
// This helper is primarily retained for tests and specialised callers. In
// normal code paths prefer CheckMassifHeight (height -> leafCount) or
// CheckLeafCount (leafCount directly) and, if needed, apply any additional
// ordinalBytes arithmetic inline.
func CheckMassifHeightFitsLeafOrdinalBytes(massifHeight uint8, ordinalBytes uint8) error {
	n := LeafCountForMassifHeight(massifHeight)

	// First enforce the uint32-backed leafCount limit so that all callers see
	// a consistent bound regardless of whether they start from massifHeight or
	// leafCount.
	if err := CheckLeafCount(n); err != nil {
		return err
	}

	// For ordinalBytes >= LeafOrdinalBytes, the CheckLeafCount constraint is
	// already the binding one.
	if ordinalBytes >= LeafOrdinalBytes {
		return nil
	}

	bits := uint64(ordinalBytes) * 8
	maxN := uint64(1) << bits

	if n > maxN {
		return fmt.Errorf("%w: massifHeight=%d requires N=%d leaves, maxN=%d for ordinalBytes=%d", ErrLeafOrdinalDoesNotFit, massifHeight, n, maxN, ordinalBytes)
	}
	return nil
}
