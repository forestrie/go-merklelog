package massifs

// Strict-decode regression tests for the checkpoint receipt CBOR wire form
// (GML15-F1). The default lenient cbor.Unmarshal accepted several encodings
// that the TS twin decoder (canopy #264, deterministic) rejects; these
// hand-assemble the receipt bytes so each case is checked independently of
// EncodeCheckpointReceiptChain, which never produces them.

import (
	"testing"

	"github.com/forestrie/go-merklelog/mmr"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// assembleReceipt builds a tag-18 COSE_Sign1 with an empty protected header,
// no signature and a single unprotected label (396, vdp), whose value is the
// one-entry map {-2: consistencyProofsValue}:
//
//	d2 84 41 a0 a1 19 01 8c a1 21 <consistencyProofsValue> f6 41 01
func assembleReceipt(consistencyProofsValue []byte) []byte {
	out := []byte{0xd2, 0x84, 0x41, 0xa0, 0xa1, 0x19, 0x01, 0x8c, 0xa1, 0x21}
	out = append(out, consistencyProofsValue...)
	return append(out, 0xf6, 0x41, 0x01)
}

// assembleReceiptVDP builds a tag-18 COSE_Sign1 whose unprotected header is
// {396: vdpMap}, with vdpMap supplied verbatim (already-encoded bytes) rather
// than the single-key {-2: ...} form assembleReceipt writes, so a test can
// construct a vdp map with duplicate or out-of-order keys:
//
//	d2 84 41 a0 a1 19 01 8c <vdpMap> f6 41 01
func assembleReceiptVDP(vdpMap []byte) []byte {
	out := []byte{0xd2, 0x84, 0x41, 0xa0, 0xa1, 0x19, 0x01, 0x8c}
	out = append(out, vdpMap...)
	return append(out, 0xf6, 0x41, 0x01)
}

// strictTestFixture builds two canonical consistency-proof byte strings
// (over the kat39 tree, sizes 1->3 and 3->7) and their canonical
// consistency-proofs array encoding, for use as the seed material each
// malformed-wire-form case mutates.
type strictTestFixture struct {
	bstr0, bstr1 []byte
	canonicalArr []byte
	inner0       []byte // the un-wrapped array content of bstr0
}

func newStrictTestFixture(t *testing.T) strictTestFixture {
	t.Helper()
	store := kat39Store(t)
	proofs := kat39ProofChain(t, store, []uint64{1, 3, 7})
	bstr0, err := EncodeConsistencyProof(proofs[0])
	require.NoError(t, err)
	bstr1, err := EncodeConsistencyProof(proofs[1])
	require.NoError(t, err)
	var inner0 []byte
	require.NoError(t, cbor.Unmarshal(bstr0, &inner0))
	canonicalArr, err := canonicalReceiptCBOR.Marshal([]cbor.RawMessage{bstr0, bstr1})
	require.NoError(t, err)
	return strictTestFixture{bstr0: bstr0, bstr1: bstr1, canonicalArr: canonicalArr, inner0: inner0}
}

// The canonical array form and the legacy bare-bstr form are exactly what
// EncodeCheckpointReceiptChain produces (for a chain and a single proof
// respectively), so both must still decode under the strict decoder.
func TestDecodeCheckpointReceiptAcceptsCanonicalForms(t *testing.T) {
	f := newStrictTestFixture(t)

	receipt, err := DecodeCheckpointReceipt(assembleReceipt(f.canonicalArr))
	require.NoError(t, err)
	require.Len(t, receipt.Proofs, 2)

	receipt, err = DecodeCheckpointReceipt(assembleReceipt(f.bstr0))
	require.NoError(t, err)
	require.Len(t, receipt.Proofs, 1)
}

// GML15-F1(a): an indefinite-length array under the vdp -2 key.
func TestDecodeCheckpointReceiptRejectsIndefiniteLengthArray(t *testing.T) {
	f := newStrictTestFixture(t)
	indef := append([]byte{0x9f}, f.bstr0...)
	indef = append(indef, f.bstr1...)
	indef = append(indef, 0xff)

	_, err := DecodeCheckpointReceipt(assembleReceipt(indef))
	require.Error(t, err)
}

// GML15-F1(b): a CBOR tag (999) wrapping the consistency-proofs array.
func TestDecodeCheckpointReceiptRejectsTaggedProofsArray(t *testing.T) {
	f := newStrictTestFixture(t)
	tagged := append([]byte{0xd9, 0x03, 0xe7}, f.canonicalArr...)

	_, err := DecodeCheckpointReceipt(assembleReceipt(tagged))
	require.Error(t, err)
}

// GML15-F1(c): duplicate -2 keys in the vdp map, {-2: bstr, -2: [bstr]} -
// the default lenient decoder silently takes the last, an accept-set
// ambiguity between implementations.
func TestDecodeCheckpointReceiptRejectsDuplicateVDPKey(t *testing.T) {
	f := newStrictTestFixture(t)
	arr1, err := canonicalReceiptCBOR.Marshal([]cbor.RawMessage{f.bstr1})
	require.NoError(t, err)
	dupVDP := append([]byte{0xa2, 0x21}, f.bstr0...)
	dupVDP = append(dupVDP, 0x21)
	dupVDP = append(dupVDP, arr1...)

	_, err = DecodeCheckpointReceipt(assembleReceiptVDP(dupVDP))
	require.Error(t, err)
}

// GML15-F1(d): non-canonical key order in the vdp map (an extra key 1 is
// written after key -2; canonical order requires the shorter/lower-valued
// key encoding, key 1 (0x01), first).
func TestDecodeCheckpointReceiptRejectsNonCanonicalVDPKeyOrder(t *testing.T) {
	f := newStrictTestFixture(t)
	badOrder := append([]byte{0xa2, 0x21}, f.canonicalArr...)
	badOrder = append(badOrder, 0x01, 0x00)

	_, err := DecodeCheckpointReceipt(assembleReceiptVDP(badOrder))
	require.Error(t, err)
}

// GML15-F1(e): a non-shortest-form integer inside a proof tuple (tree-size-1
// of 1 encoded as `1a 00000001` instead of `01`).
func TestDecodeCheckpointReceiptRejectsNonShortestFormInt(t *testing.T) {
	f := newStrictTestFixture(t)
	require.Equal(t, byte(0x84), f.inner0[0], "proof tuple is a 4-element array")
	require.Equal(t, byte(0x01), f.inner0[1], "tree-size-1 is the shortest-form uint 1")
	nonShortest := append([]byte{0x84, 0x1a, 0, 0, 0, 1}, f.inner0[2:]...)
	nonShortestBstr, err := canonicalReceiptCBOR.Marshal(nonShortest)
	require.NoError(t, err)

	_, err = DecodeCheckpointReceipt(assembleReceipt(nonShortestBstr))
	require.Error(t, err)
}

// GML15-F1(f): a consistency-proofs array element that is a CBOR array of
// small unsigned integers rather than a byte string - fxamacker will decode
// an int array straight into a []byte if this is not rejected by major type.
func TestDecodeCheckpointReceiptRejectsIntArrayElement(t *testing.T) {
	f := newStrictTestFixture(t)
	ints := make([]uint64, len(f.inner0))
	for i, b := range f.inner0 {
		ints[i] = uint64(b)
	}
	intArrElem, err := canonicalReceiptCBOR.Marshal(ints)
	require.NoError(t, err)
	arr, err := canonicalReceiptCBOR.Marshal([]cbor.RawMessage{intArrElem})
	require.NoError(t, err)

	_, err = DecodeCheckpointReceipt(assembleReceipt(arr))
	require.Error(t, err)
}

// A 5-element proof tuple is rejected: EncodeConsistencyProof/
// DecodeConsistencyProof fix the arity at 4 (tree-size-1, tree-size-2,
// paths, right-peaks), and fxamacker's `,toarray` already enforces an exact
// element count, but the profile depends on that holding, so it is pinned
// here as a regression guard.
func TestDecodeCheckpointReceiptRejectsFiveElementTuple(t *testing.T) {
	f := newStrictTestFixture(t)
	require.Equal(t, byte(0x84), f.inner0[0])
	fiveElem := append([]byte{0x85}, f.inner0[1:]...)
	fiveElem = append(fiveElem, 0x00)
	fiveElemBstr, err := canonicalReceiptCBOR.Marshal(fiveElem)
	require.NoError(t, err)

	_, err = DecodeCheckpointReceipt(assembleReceipt(fiveElemBstr))
	require.Error(t, err)
}

// Regression guard: a receipt produced by SignCheckpointReceipt with
// WithPeakReceipts and WithUnprotectedExtras - both of which carry tagged
// COSE_Sign1 / caller-supplied CBOR values in the unprotected header - must
// still decode under the strict decoder. TagsMd is deliberately left at its
// default (tags allowed) for exactly this reason.
func TestDecodeCheckpointReceiptAcceptsTaggedUnprotectedValues(t *testing.T) {
	store := kat39Store(t)
	proof, err := BuildConsistencyProof(store, 4, 7)
	require.NoError(t, err)
	accumulator, err := mmr.PeakHashes(store, 6)
	require.NoError(t, err)

	signer, _ := newES256Signer(t)
	delegation, err := canonicalReceiptCBOR.Marshal(map[string]any{"note": "delegation-material"})
	require.NoError(t, err)

	data, err := SignCheckpointReceipt(signer, proof, accumulator,
		WithPeakReceipts([]byte("kid-1")),
		WithUnprotectedExtras(map[int64]cbor.RawMessage{SealDelegationProofLabel: delegation}))
	require.NoError(t, err)

	receipt, err := DecodeCheckpointReceipt(data)
	require.NoError(t, err)
	require.Len(t, receipt.Proofs, 1)
	require.NotEmpty(t, receipt.PeakReceipts)
	require.Contains(t, receipt.Extras, SealDelegationProofLabel)
}

// A null inner path (f6) where an empty array (80) belongs: the draft CDDL
// has no null there and the TS decoder rejects it, so the Go decoder rejects
// it too. Objects sealed before EncodeConsistencyProof normalised a nil
// inner path carry this form and are re-sealed rather than tolerated.
func TestDecodeConsistencyProofRejectsNullInnerPath(t *testing.T) {
	store := kat39Store(t)
	proof, err := BuildConsistencyProof(store, 3, 4)
	require.NoError(t, err)
	require.Len(t, proof.Paths, 1)
	require.Nil(t, proof.Paths[0], "fixture proof has a nil inner path")

	canonicalBstr, err := EncodeConsistencyProof(proof)
	require.NoError(t, err)

	var inner []byte
	require.NoError(t, cbor.Unmarshal(canonicalBstr, &inner))
	// inner = 84 <ts1> <ts2> 81 80 81 5820<peak>: index 4 is the lone empty
	// inner path (80). A CBOR null (f6) is the same one byte, so swapping it
	// in place leaves the bstr framing untouched.
	require.Equal(t, byte(0x81), inner[3], "Paths outer array marker")
	require.Equal(t, byte(0x80), inner[4], "the lone empty inner path")
	nullInner := append([]byte{}, inner...)
	nullInner[4] = 0xf6
	nullBstr, err := canonicalReceiptCBOR.Marshal(nullInner)
	require.NoError(t, err)

	gotCanonical, err := DecodeConsistencyProof(canonicalBstr)
	require.NoError(t, err)
	require.Empty(t, gotCanonical.Paths[0])

	_, err = DecodeConsistencyProof(nullBstr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "path 0 is null")
}
