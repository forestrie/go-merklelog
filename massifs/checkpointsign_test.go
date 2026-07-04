package massifs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/fxamacker/cbor/v2"

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

// The univocity on-chain P256 verifier rejects malleable high-s signatures;
// raw ECDSA signing produces them ~50% of the time. All emitted checkpoint
// material must be in low-s form and still verify.
func TestSignCheckpointReceiptEmitsLowSSignatures(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer := mlcose.NewTestCoseSigner(t, *key)
	verifier := newES256Verifier(t, &key.PublicKey)

	store, sizes := newFixtureMMR(t, 3)
	proof, err := BuildConsistencyProof(store, 0, sizes[2])
	require.NoError(t, err)
	accumulator, err := mmr.PeakHashes(store, sizes[2]-1)
	require.NoError(t, err)

	halfN := new(big.Int).Rsh(elliptic.P256().Params().N, 1)
	// 32 independent signatures: all-low-s by chance is ~2^-32.
	for range 32 {
		data, err := SignCheckpointReceipt(signer, proof, accumulator, WithPeakReceipts(nil))
		require.NoError(t, err)
		r, err := DecodeCheckpointReceipt(data)
		require.NoError(t, err)

		sigs := append([][]byte{r.Signature}, decodePeakReceiptSignatures(t, r.PeakReceipts)...)
		for _, sig := range sigs {
			require.Len(t, sig, 64)
			s := new(big.Int).SetBytes(sig[32:])
			require.LessOrEqual(t, s.Cmp(halfN), 0, "signature s must be in the lower half order")
		}
		_, err = VerifyCheckpointReceipt(store, &r, verifier)
		require.NoError(t, err)
	}
}

func decodePeakReceiptSignatures(t *testing.T, receipts [][]byte) [][]byte {
	t.Helper()
	var sigs [][]byte
	for _, rb := range receipts {
		var tag cbor.RawTag
		require.NoError(t, cbor.Unmarshal(rb, &tag))
		var arr []cbor.RawMessage
		require.NoError(t, cbor.Unmarshal(tag.Content, &arr))
		var sig []byte
		require.NoError(t, cbor.Unmarshal(arr[3], &sig))
		sigs = append(sigs, sig)
	}
	return sigs
}
