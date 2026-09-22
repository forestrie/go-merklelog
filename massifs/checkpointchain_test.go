package massifs

// A checkpoint receipt that relays several sealed steps under one signature
// (ADR-0066 D2): the wire form is the draft's `consistency-proofs = [ +
// consistency-proof ]`, the fold walks the chain from trusted state, and the
// signed tree-size-2 is the last proof's.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"

	mlcose "github.com/forestrie/go-merklelog/massifs/cose"
	"github.com/forestrie/go-merklelog/mmr"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

// kat39Store loads the canonical 39-node MMR from the pinned KAT vectors, so
// that a chain built here is over the same tree every implementation of the
// profile is tested against.
func kat39Store(t *testing.T) *memNodes {
	t.Helper()
	f := kat39Load(t)
	store := &memNodes{}
	for _, h := range f.Tree.NodesHex {
		store.nodes = append(store.nodes, kat39Bytes(t, h))
	}
	require.Len(t, store.nodes, 39)
	return store
}

// kat39ProofChain builds one consistency proof per step of sizes, the first from
// the size preceding it in the slice.
func kat39ProofChain(t *testing.T, store *memNodes, sizes []uint64) []ConsistencyProof {
	t.Helper()
	proofs := make([]ConsistencyProof, 0, len(sizes)-1)
	for i := 1; i < len(sizes); i++ {
		proof, err := BuildConsistencyProof(store, sizes[i-1], sizes[i])
		require.NoError(t, err)
		proofs = append(proofs, proof)
	}
	return proofs
}

func newES256Signer(t *testing.T) (cose.Signer, cose.Verifier) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return mlcose.NewTestCoseSigner(t, *key), newES256Verifier(t, &key.PublicKey)
}

// A receipt carrying three proofs survives the round trip with the chain in
// order, and the compatibility Proof field is the last link, the one the
// protected header signs.
func TestCheckpointReceiptChainRoundTrip(t *testing.T) {
	store := kat39Store(t)
	proofs := kat39ProofChain(t, store, []uint64{1, 3, 4, 7})
	require.Len(t, proofs, 3)

	encoded, err := EncodeCheckpointReceiptChain(
		[]byte{0xa0}, proofs, []byte{0x01, 0x02})
	require.NoError(t, err)
	got, err := DecodeCheckpointReceipt(encoded)
	require.NoError(t, err)

	require.Equal(t, proofs, got.Proofs)
	require.Equal(t, proofs[2], got.Proof)
	require.Equal(t, []byte{0xa0}, got.ProtectedHeader)
	require.Equal(t, []byte{0x01, 0x02}, got.Signature)
}

// The single-proof encoder writes the same array of one, which the decoder
// reads back as a chain of length one.
func TestCheckpointReceiptSingleProofIsAChainOfOne(t *testing.T) {
	store := kat39Store(t)
	proof, err := BuildConsistencyProof(store, 4, 7)
	require.NoError(t, err)

	encoded, err := EncodeCheckpointReceipt([]byte{0xa0}, proof, []byte{0x01})
	require.NoError(t, err)
	got, err := DecodeCheckpointReceipt(encoded)
	require.NoError(t, err)

	require.Equal(t, []ConsistencyProof{proof}, got.Proofs)
	require.Equal(t, proof, got.Proof)
}

// A chain over the canonical tree verifies from the accumulator of its first
// proof's origin: each step is folded onto the previous step's result, and
// the accumulator the last step reaches is the one the signature covers.
func TestVerifyCheckpointReceiptFromStateFoldsTheChain(t *testing.T) {
	store := kat39Store(t)
	sizes := []uint64{1, 3, 4, 7}
	proofs := kat39ProofChain(t, store, sizes)
	target, err := mmr.PeakHashes(store, sizes[3]-1)
	require.NoError(t, err)

	signer, verifier := newES256Signer(t)
	encoded, err := SignCheckpointReceiptChain(signer, proofs, target)
	require.NoError(t, err)
	receipt, err := DecodeCheckpointReceipt(encoded)
	require.NoError(t, err)

	signed, err := ProtectedHeaderTreeSize(receipt.ProtectedHeader)
	require.NoError(t, err)
	require.Equal(t, sizes[3], signed)

	trusted, err := mmr.PeakHashes(store, sizes[0]-1)
	require.NoError(t, err)
	accumulator, err := VerifyCheckpointReceiptFromState(
		sizes[0], trusted, &receipt, verifier)
	require.NoError(t, err)
	require.Equal(t, target, accumulator)

	// The chain applies to the size it starts at and no other.
	_, err = VerifyCheckpointReceiptFromState(sizes[1], trusted, &receipt, verifier)
	require.ErrorIs(t, err, ErrConsistencyProofCheck)
}

// A chain whose middle proof does not start where its predecessor ended is
// two unrelated extensions presented as one. The intermediate sizes carry no
// signature of their own, so the comparison against the previous step is the
// only thing that links them.
func TestVerifyCheckpointReceiptFromStateRejectsNonContiguousChain(t *testing.T) {
	store := kat39Store(t)
	sizes := []uint64{1, 3, 4, 7}
	proofs := kat39ProofChain(t, store, sizes)
	target, err := mmr.PeakHashes(store, sizes[3]-1)
	require.NoError(t, err)
	trusted, err := mmr.PeakHashes(store, sizes[0]-1)
	require.NoError(t, err)

	signer, verifier := newES256Signer(t)
	encoded, err := SignCheckpointReceiptChain(signer, proofs, target)
	require.NoError(t, err)
	receipt, err := DecodeCheckpointReceipt(encoded)
	require.NoError(t, err)

	// The middle proof declares an origin one node below the size its
	// predecessor reached.
	broken := cloneReceipt(receipt)
	broken.Proofs[1].TreeSize1 = sizes[1] - 1
	_, err = VerifyCheckpointReceiptFromState(sizes[0], trusted, &broken, verifier)
	require.ErrorIs(t, err, ErrProofChainNotContiguous)

	// And one above it.
	broken = cloneReceipt(receipt)
	broken.Proofs[1].TreeSize1 = sizes[1] + 1
	_, err = VerifyCheckpointReceiptFromState(sizes[0], trusted, &broken, verifier)
	require.ErrorIs(t, err, ErrProofChainNotContiguous)

	// The store-backed path has no trusted base to fold from, but the links
	// must still join.
	_, err = VerifyCheckpointReceipt(store, &broken, verifier)
	require.ErrorIs(t, err, ErrProofChainNotContiguous)
}

// The signed size is the last proof's. A receipt signed over an intermediate
// step's accumulator and relayed with the whole chain leaves the final
// accumulator unsigned, and is rejected before the fold runs.
func TestVerifyCheckpointReceiptRejectsSignedIntermediateSize(t *testing.T) {
	store := kat39Store(t)
	sizes := []uint64{1, 3, 4, 7}
	proofs := kat39ProofChain(t, store, sizes)
	trusted, err := mmr.PeakHashes(store, sizes[0]-1)
	require.NoError(t, err)
	middle, err := mmr.PeakHashes(store, sizes[2]-1)
	require.NoError(t, err)

	// A genuine two-step receipt to size 4: header, payload and signature are
	// the sealer's own.
	signer, verifier := newES256Signer(t)
	encoded, err := SignCheckpointReceiptChain(signer, proofs[:2], middle)
	require.NoError(t, err)
	toMiddle, err := DecodeCheckpointReceipt(encoded)
	require.NoError(t, err)
	_, err = VerifyCheckpointReceiptFromState(sizes[0], trusted, &toMiddle, verifier)
	require.NoError(t, err)

	// The third step appended under that signature: the signed size is now
	// the second proof's, not the last's.
	relayed, err := EncodeCheckpointReceiptChain(
		toMiddle.ProtectedHeader, proofs, toMiddle.Signature)
	require.NoError(t, err)
	receipt, err := DecodeCheckpointReceipt(relayed)
	require.NoError(t, err)

	_, err = VerifyCheckpointReceiptFromState(sizes[0], trusted, &receipt, verifier)
	require.ErrorIs(t, err, ErrSignedSizeMismatch)
	_, err = VerifyCheckpointReceipt(store, &receipt, verifier)
	require.ErrorIs(t, err, ErrSignedSizeMismatch)
}

// A receipt proves something or it is not a receipt of consistency: an empty
// consistency-proofs array is rejected where it is read, and never produced.
func TestCheckpointReceiptRejectsEmptyProofChain(t *testing.T) {
	_, err := EncodeCheckpointReceiptChain([]byte{0xa0}, nil, []byte{0x01})
	require.ErrorIs(t, err, ErrProofChainEmpty)

	signer, verifier := newES256Signer(t)
	_, err = SignCheckpointReceiptChain(signer, nil, [][]byte{{0x00}})
	require.ErrorIs(t, err, ErrProofChainEmpty)

	empty, err := canonicalReceiptCBOR.Marshal([]cbor.RawMessage{})
	require.NoError(t, err)
	verifiableProofs, err := canonicalReceiptCBOR.Marshal(
		map[int64]cbor.RawMessage{checkpointKeyConsistencyProof: empty})
	require.NoError(t, err)
	sign1 := []any{[]byte{0xa0},
		map[int64]cbor.RawMessage{checkpointLabelVDP: verifiableProofs},
		nil, []byte{0x01}}
	encoded, err := canonicalReceiptCBOR.Marshal(cbor.Tag{Number: 18, Content: sign1})
	require.NoError(t, err)

	_, err = DecodeCheckpointReceipt(encoded)
	require.ErrorIs(t, err, ErrProofChainEmpty)

	// A receipt assembled in memory rather than decoded reaches the
	// verifiers with no chain at all.
	var bare CheckpointReceipt
	_, err = VerifyCheckpointReceiptFromState(0, nil, &bare, verifier)
	require.ErrorIs(t, err, ErrProofChainEmpty)
}
