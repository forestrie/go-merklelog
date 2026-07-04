package massifs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	mlcose "github.com/forestrie/go-merklelog/massifs/cose"
	"github.com/forestrie/go-merklelog/mmr"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

// signFixtureCheckpoint signs a format-v3 checkpoint receipt over the fixture
// mmr for fromSize -> toSize with a fresh ES256 key, returning the decoded
// receipt and the signing key.
func signFixtureCheckpoint(
	t *testing.T, store *memNodes, fromSize, toSize uint64,
) (CheckpointReceipt, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer := mlcose.NewTestCoseSigner(t, *key)

	proof, err := BuildConsistencyProof(store, fromSize, toSize)
	require.NoError(t, err)
	accumulator, err := mmr.PeakHashes(store, toSize-1)
	require.NoError(t, err)

	data, err := SignCheckpointReceipt(signer, proof, accumulator)
	require.NoError(t, err)
	receipt, err := DecodeCheckpointReceipt(data)
	require.NoError(t, err)
	return receipt, key
}

func newES256Verifier(t *testing.T, pub *ecdsa.PublicKey) cose.Verifier {
	t.Helper()
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, pub)
	require.NoError(t, err)
	return verifier
}

func TestVerifyCheckpointReceiptVerifies(t *testing.T) {
	store, sizes := newFixtureMMR(t, 7)

	// A first checkpoint (no previous seal) and a chained one.
	for _, fromSize := range []uint64{0, sizes[2]} {
		receipt, key := signFixtureCheckpoint(t, store, fromSize, sizes[6])

		accumulator, err := VerifyCheckpointReceipt(
			store, &receipt, newES256Verifier(t, &key.PublicKey))
		require.NoError(t, err)

		expected, err := mmr.PeakHashes(store, sizes[6]-1)
		require.NoError(t, err)
		require.Equal(t, expected, accumulator)
	}
}

func TestVerifyCheckpointReceiptRequiresVerifier(t *testing.T) {
	store, sizes := newFixtureMMR(t, 3)
	receipt, _ := signFixtureCheckpoint(t, store, 0, sizes[2])

	_, err := VerifyCheckpointReceipt(store, &receipt, nil)
	require.ErrorIs(t, err, ErrVerifierRequired)
}

func TestVerifyCheckpointReceiptTamperedSignatureFails(t *testing.T) {
	store, sizes := newFixtureMMR(t, 3)
	receipt, key := signFixtureCheckpoint(t, store, 0, sizes[2])

	receipt.Signature[7] ^= 0x01
	_, err := VerifyCheckpointReceipt(store, &receipt, newES256Verifier(t, &key.PublicKey))
	require.ErrorIs(t, err, ErrSealVerifyFailed)
}

func TestVerifyCheckpointReceiptWrongKeyFails(t *testing.T) {
	store, sizes := newFixtureMMR(t, 3)
	receipt, _ := signFixtureCheckpoint(t, store, 0, sizes[2])

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, err = VerifyCheckpointReceipt(store, &receipt, newES256Verifier(t, &otherKey.PublicKey))
	require.ErrorIs(t, err, ErrSealVerifyFailed)
}

func TestVerifyCheckpointReceiptTamperedLogFails(t *testing.T) {
	store, sizes := newFixtureMMR(t, 3)
	receipt, key := signFixtureCheckpoint(t, store, 0, sizes[2])

	// Tamper a peak node after sealing: the accumulator recovered from the
	// massif no longer matches the signed detached payload. (Tampering under
	// a peak is caught by consistency/inclusion checks, not the seal.)
	store.nodes[len(store.nodes)-1][0] ^= 0x01
	_, err := VerifyCheckpointReceipt(store, &receipt, newES256Verifier(t, &key.PublicKey))
	require.ErrorIs(t, err, ErrSealVerifyFailed)
}

func TestVerifyCheckpointReceiptTamperedProofSizeFails(t *testing.T) {
	store, sizes := newFixtureMMR(t, 7)
	receipt, key := signFixtureCheckpoint(t, store, 0, sizes[6])

	// Claiming a different (valid, complete) sealed size changes the derived
	// accumulator, so the signature check fails.
	receipt.Proof.TreeSize2 = sizes[2]
	_, err := VerifyCheckpointReceipt(store, &receipt, newES256Verifier(t, &key.PublicKey))
	require.ErrorIs(t, err, ErrSealVerifyFailed)
}
