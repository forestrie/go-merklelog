package massifs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

	// The signed tree-size-2 equals the proof's (ADR-0066).
	signed, err := ProtectedHeaderTreeSize(r.ProtectedHeader)
	require.NoError(t, err)
	require.Equal(t, proof.TreeSize2, signed)

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

// SignCheckpointReceipt's protected header must byte-match across
// implementations (ADR-0066; the fxamacker canonical encoder places the three
// labels in the order 1, 395, -65933, which is both RFC 7049 length-first and
// RFC 8949 bytewise order for these keys). These vectors are cross-language
// KAT material.
func TestSignCheckpointReceiptProtectedHeaderExactBytes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		s1, s2     uint64
		wantHeader string
	}{
		{"sizes 0,1", 0, 1, "a3012619018b033a0001018c01"},
		{"sizes 7,8", 7, 8, "a3012619018b033a0001018c08"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			signer := mlcose.NewTestCoseSigner(t, *key)

			peak := make([]byte, 32)
			peak[0] = 0x11
			proof := ConsistencyProof{
				TreeSize1:  tc.s1,
				TreeSize2:  tc.s2,
				Paths:      [][][]byte{},
				RightPeaks: [][]byte{peak},
			}

			receiptBytes, err := SignCheckpointReceipt(signer, proof, [][]byte{peak})
			require.NoError(t, err)
			r, err := DecodeCheckpointReceipt(receiptBytes)
			require.NoError(t, err)

			require.Equal(t, tc.wantHeader, hex.EncodeToString(r.ProtectedHeader))

			signed, err := ProtectedHeaderTreeSize(r.ProtectedHeader)
			require.NoError(t, err)
			require.Equal(t, tc.s2, signed)
		})
	}
}

// ProtectedHeaderTreeSize must reject a protected header signed before
// ADR-0066: the {1: alg, 395: vds} form carries no tree-size label.
func TestProtectedHeaderTreeSizeErrorsWithoutLabel(t *testing.T) {
	protected, err := canonicalReceiptCBOR.Marshal(map[int64]any{
		checkpointLabelAlg: int64(-7),
		checkpointLabelVDS: CheckpointVDSConsistency,
	})
	require.NoError(t, err)

	_, err = ProtectedHeaderTreeSize(protected)
	require.ErrorIs(t, err, ErrSignedSizeMissing)

	// The algorithm is still readable from the old form.
	alg, err := ProtectedHeaderAlgorithm(protected)
	require.NoError(t, err)
	require.Equal(t, int64(-7), alg)
}

// The protected header is signed as opaque bytes, so it must have exactly
// one reading: every non-canonical encoding of {1: -7, 395: 3, -65933: 8} is
// rejected rather than decoded, so a canonical parser (the contract) and this
// reader cannot disagree on the signed size.
func TestProtectedHeaderTreeSizeRejectsNonCanonicalHeaders(t *testing.T) {
	for _, tc := range []struct {
		name string
		hex  string
	}{
		{"duplicate size label, 4 then 8", "a4012619018b033a0001018c043a0001018c08"},
		{"non-canonical uint for 8", "a3012619018b033a0001018c1a00000008"},
		{"non-canonical uint for 8 (1 byte form)", "a3012619018b033a0001018c1808"},
		{"indefinite-length map", "bf012619018b033a0001018c08ff"},
		{"reversed key order", "a33a0001018c0819018b030126"},
		{"tagged size", "a3012619018b033a0001018cc108"},
		{"bignum size", "a3012619018b033a0001018cc24108"},
		{"float size", "a3012619018b033a0001018cf94800"},
		{"negative size", "a3012619018b033a0001018c27"},
		{"trailing byte", "a3012619018b033a0001018c0800"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header, err := hex.DecodeString(tc.hex)
			require.NoError(t, err)
			_, err = ProtectedHeaderTreeSize(header)
			require.ErrorIs(t, err, ErrProtectedHeaderInvalid)
		})
	}

	// The canonical form of the same map is accepted.
	header, err := hex.DecodeString("a3012619018b033a0001018c08")
	require.NoError(t, err)
	signed, err := ProtectedHeaderTreeSize(header)
	require.NoError(t, err)
	require.Equal(t, uint64(8), signed)
}

// ProtectedHeaderTreeSize round-trips the size SignCheckpointReceipt signs.
func TestProtectedHeaderTreeSizeRoundTrip(t *testing.T) {
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

	signed, err := ProtectedHeaderTreeSize(r.ProtectedHeader)
	require.NoError(t, err)
	require.Equal(t, proof.TreeSize2, signed)
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
