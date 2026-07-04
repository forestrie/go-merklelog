package massifs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"

	commoncbor "github.com/forestrie/go-merklelog/massifs/cbor"
	commoncose "github.com/forestrie/go-merklelog/massifs/cose"
	"github.com/forestrie/go-merklelog/mmr"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

// The sealer opts in to pre-signed peak receipts: one detached-payload
// COSE_Sign1 per accumulator peak rides the checkpoint's unprotected header
// under the private SealPeakReceiptsLabel, with a slim {alg, vds, kid}
// protected header. Each signature verifies over the peak it commits to.
func TestSignCheckpointReceiptWithPeakReceipts(t *testing.T) {
	store, sizes := newFixtureMMR(t, 7)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer := commoncose.NewTestCoseSigner(t, *key)
	verifier := newES256Verifier(t, &key.PublicKey)

	proof, err := BuildConsistencyProof(store, 0, sizes[6])
	require.NoError(t, err)
	accumulator, err := mmr.PeakHashes(store, sizes[6]-1)
	require.NoError(t, err)
	require.Greater(t, len(accumulator), 1, "fixture must have multiple peaks")

	kid := []byte("log-key-1")
	data, err := SignCheckpointReceipt(signer, proof, accumulator, WithPeakReceipts(kid))
	require.NoError(t, err)

	r, err := DecodeCheckpointReceipt(data)
	require.NoError(t, err)
	require.Len(t, r.PeakReceipts, len(accumulator))

	for i, receiptBytes := range r.PeakReceipts {
		msg, err := commoncose.NewCoseSign1MessageFromCBOR(
			receiptBytes, commoncose.WithDecOptions(commoncbor.DecOptions))
		require.NoError(t, err)

		alg, err := msg.Headers.Protected.Algorithm()
		require.NoError(t, err)
		require.Equal(t, cose.AlgorithmES256, alg)
		require.Equal(t, kid, msg.Headers.Protected[cose.HeaderLabelKeyID],
			"peak receipt %d must carry the signing key id", i)
		_, hasCWT := msg.Headers.Protected[commoncose.HeaderLabelCWTClaims]
		require.False(t, hasCWT, "slim peak receipts carry no CWT key material")

		// The detached payload is the peak itself (draft-bryce Receipt of
		// Inclusion); reattach it and verify the signature.
		msg.Payload = accumulator[i]
		require.NoError(t, msg.Verify(nil, verifier), "peak receipt %d signature", i)

		// A different peak must not verify.
		msg.Payload = accumulator[(i+1)%len(accumulator)]
		require.Error(t, msg.Verify(nil, verifier))
	}

	// Peak receipts are strictly opt-in.
	data, err = SignCheckpointReceipt(signer, proof, accumulator)
	require.NoError(t, err)
	r, err = DecodeCheckpointReceipt(data)
	require.NoError(t, err)
	require.Empty(t, r.PeakReceipts)
}

// Any holder of the checkpoint and replicated massif data mints a verifiable
// receipt of inclusion for any node under the seal, offline, with no signing
// key involved.
func TestNewReceiptMintsVerifiableInclusionReceipts(t *testing.T) {
	mc := buildLegacyBlobMassif0(t, 1 /*blobVersion*/, 3 /*massifHeight*/, 3 /*leaves*/)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer := commoncose.NewTestCoseSigner(t, *key)
	verifier := newES256Verifier(t, &key.PublicKey)

	proof, err := BuildConsistencyProof(&mc, 0, mc.RangeCount())
	require.NoError(t, err)
	accumulator, err := mmr.PeakHashes(&mc, mc.RangeCount()-1)
	require.NoError(t, err)
	require.Greater(t, len(accumulator), 1, "fixture must exercise peak selection")

	signed, err := SignCheckpointReceipt(signer, proof, accumulator, WithPeakReceipts([]byte("log-key-1")))
	require.NoError(t, err)
	store := newMemStore(mc.Data, signed)

	// Every node under the seal is receiptable, not just leaves.
	for mmrIndex := range mc.RangeCount() {
		candidate, err := mc.Get(mmrIndex)
		require.NoError(t, err)

		receipt, err := NewReceipt(context.Background(), store, verifier, 3, mmrIndex)
		require.NoError(t, err)

		// Round-trip the receipt as a relying party would receive it.
		encoded, err := receipt.MarshalCBOR()
		require.NoError(t, err)
		decoded, err := commoncose.NewCoseSign1MessageFromCBOR(
			encoded, commoncose.WithDecOptions(commoncbor.DecOptions))
		require.NoError(t, err)

		ok, root, err := VerifySignedInclusionReceipt(context.Background(), decoded, verifier, candidate)
		require.NoError(t, err, "receipt for mmr index %d", mmrIndex)
		require.True(t, ok)
		require.NotEmpty(t, root)

		// A tampered candidate must not verify.
		tampered := append([]byte(nil), candidate...)
		tampered[0] ^= 0x01
		ok, _, err = VerifySignedInclusionReceipt(context.Background(), decoded, verifier, tampered)
		require.False(t, ok)
		require.Error(t, err)
	}
}

func TestNewReceiptRequiresPeakReceipts(t *testing.T) {
	mc := buildLegacyBlobMassif0(t, 1, 3, 2)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer := commoncose.NewTestCoseSigner(t, *key)

	proof, err := BuildConsistencyProof(&mc, 0, mc.RangeCount())
	require.NoError(t, err)
	accumulator, err := mmr.PeakHashes(&mc, mc.RangeCount()-1)
	require.NoError(t, err)

	// Sealed without peak receipts: minting must fail with a clear error.
	signed, err := SignCheckpointReceipt(signer, proof, accumulator)
	require.NoError(t, err)
	store := newMemStore(mc.Data, signed)

	_, err = NewReceipt(context.Background(), store, newES256Verifier(t, &key.PublicKey), 3, 0)
	require.ErrorContains(t, err, "no pre-signed peak receipts")
}

// Unmodelled unprotected labels (delegation material) round-trip through
// encode/decode via Extras, without affecting the checkpoint signature.
func TestCheckpointReceiptUnprotectedExtrasRoundTrip(t *testing.T) {
	store, sizes := newFixtureMMR(t, 3)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer := commoncose.NewTestCoseSigner(t, *key)

	proof, err := BuildConsistencyProof(store, 0, sizes[2])
	require.NoError(t, err)
	accumulator, err := mmr.PeakHashes(store, sizes[2]-1)
	require.NoError(t, err)

	delegation, err := cbor.Marshal([]byte("opaque-delegation-material"))
	require.NoError(t, err)

	data, err := SignCheckpointReceipt(
		signer, proof, accumulator,
		WithPeakReceipts([]byte("kid")),
		WithUnprotectedExtras(map[int64]cbor.RawMessage{SealDelegationProofLabel: delegation}))
	require.NoError(t, err)

	r, err := DecodeCheckpointReceipt(data)
	require.NoError(t, err)
	require.Equal(t, cbor.RawMessage(delegation), r.Extras[SealDelegationProofLabel])
	require.NotContains(t, r.Extras, SealPeakReceiptsLabel, "modelled labels are not duplicated into Extras")

	// The extras ride outside the signature: the receipt still verifies.
	_, err = VerifyCheckpointReceipt(store, &r, newES256Verifier(t, &key.PublicKey))
	require.NoError(t, err)
}
