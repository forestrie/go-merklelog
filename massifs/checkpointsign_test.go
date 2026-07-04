package massifs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	mlcose "github.com/forestrie/go-merklelog/massifs/cose"
	"github.com/forestrie/go-merklelog/mmr"
	"github.com/stretchr/testify/require"
)

// The sealer's core emission: sign the detached raw-concat payload with the
// log's COSE signer and encode a format-v3 receipt. The receipt decodes to the
// proof and a signature that verifies (as the contract would) over the
// Sig_structure of the reconstructed accumulator.
func TestSignCheckpointReceiptProducesVerifiableES256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer := mlcose.NewTestCoseSigner(t, *key)

	store, sizes := newFixtureMMR(t, 3)
	proof, err := BuildConsistencyProof(store, 0, sizes[2])
	require.NoError(t, err)
	accumulator, err := mmr.PeakHashes(store, sizes[2]-1)
	require.NoError(t, err)

	receiptBytes, err := SignCheckpointReceipt(signer, proof, accumulator)
	require.NoError(t, err)

	r, err := DecodeCheckpointReceipt(receiptBytes)
	require.NoError(t, err)
	require.Equal(t, proof, r.Proof)

	// ES256 algorithm is readable from the protected header (as the contract
	// reads it from label 1).
	alg, err := ProtectedHeaderAlgorithm(r.ProtectedHeader)
	require.NoError(t, err)
	require.Equal(t, int64(-7), alg)

	// A first-checkpoint accumulator is exactly the proof's right-peaks; verify
	// the ES256 signature over the Sig_structure of that detached payload.
	detached := DetachedPayload(r.Proof.RightPeaks)
	require.Equal(t, DetachedPayload(accumulator), detached)
	digest := sha256.Sum256(SigStructure(r.ProtectedHeader, detached))
	require.Len(t, r.Signature, 64)
	rr := new(big.Int).SetBytes(r.Signature[:32])
	ss := new(big.Int).SetBytes(r.Signature[32:])
	require.True(t, ecdsa.Verify(&key.PublicKey, digest[:], rr, ss),
		"receipt signature must verify against the signer key")
}
