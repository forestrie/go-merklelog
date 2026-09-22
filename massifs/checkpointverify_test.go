package massifs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math"
	"testing"

	"github.com/fxamacker/cbor/v2"

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

// cloneReceipt copies a receipt and its proof chain, so that a case which
// alters one link leaves the other cases' receipts as they were: the chain is
// a slice, and a struct copy shares its backing array.
func cloneReceipt(r CheckpointReceipt) CheckpointReceipt {
	c := r
	c.Proofs = append([]ConsistencyProof(nil), r.Proofs...)
	return c
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

// A declared sealed size other than the signed one is rejected by the signed
// size comparison before any accumulator is read: the same signed peaks would
// otherwise be read at another height (ADR-0066). tree-size-1 is unsigned
// prover context: changing it does not affect the store-backed verifier,
// which reads the accumulator at tree-size-2 only.
func TestVerifyCheckpointReceiptReplacedProofSizeFails(t *testing.T) {
	store, sizes := newFixtureMMR(t, 7)
	receipt, key := signFixtureCheckpoint(t, store, 0, sizes[6])
	verifier := newES256Verifier(t, &key.PublicKey)

	receipt.Proofs[0].TreeSize2 = sizes[2]
	_, err := VerifyCheckpointReceipt(store, &receipt, verifier)
	require.ErrorIs(t, err, ErrSignedSizeMismatch)

	receipt.Proofs[0].TreeSize2 = sizes[6]
	receipt.Proofs[0].TreeSize1 = sizes[1]
	_, err = VerifyCheckpointReceipt(store, &receipt, verifier)
	require.NoError(t, err)
}

// A signed tree-size-2 that is not a complete mmr size, including 2^64-1
// where the peak computation wraps, is rejected instead of being read as an
// empty accumulator.
func TestVerifyCheckpointReceiptRejectsIncompleteSignedSize(t *testing.T) {
	store, _ := newFixtureMMR(t, 7)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer := mlcose.NewTestCoseSigner(t, *key)
	verifier := newES256Verifier(t, &key.PublicKey)

	sign := func(size uint64) CheckpointReceipt {
		proof := ConsistencyProof{TreeSize1: 0, TreeSize2: size, Paths: [][][]byte{}, RightPeaks: [][]byte{}}
		data, err := SignCheckpointReceipt(signer, proof, nil)
		require.NoError(t, err)
		receipt, err := DecodeCheckpointReceipt(data)
		require.NoError(t, err)
		return receipt
	}
	for _, size := range []uint64{2, 5, 6, 9, math.MaxUint64 - 1} {
		receipt := sign(size)
		_, err = VerifyCheckpointReceipt(store, &receipt, verifier)
		require.ErrorIs(t, err, mmr.ErrIncompleteTreeSize, "size %d", size)
		_, err = VerifyCheckpointReceiptFromState(0, nil, &receipt, verifier)
		require.ErrorIs(t, err, mmr.ErrIncompleteTreeSize, "size %d", size)
	}

	// 2^64-1 is a complete one-peak size, but the peak computation wraps and
	// reads no peaks: the empty accumulator must not be signed over.
	receipt := sign(math.MaxUint64)
	acc, err := VerifyCheckpointReceipt(store, &receipt, verifier)
	require.ErrorIs(t, err, ErrSealVerifyFailed)
	require.Nil(t, acc)
	_, err = VerifyCheckpointReceiptFromState(0, nil, &receipt, verifier)
	require.ErrorIs(t, err, ErrConsistencyProofCheck)
}

// A protected header without the size label (the {alg, vds} form) is
// rejected: the size must be signed.
func TestVerifyCheckpointReceiptRequiresSignedSize(t *testing.T) {
	store, sizes := newFixtureMMR(t, 3)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer := mlcose.NewTestCoseSigner(t, *key)

	proof, err := BuildConsistencyProof(store, 0, sizes[2])
	require.NoError(t, err)
	accumulator, err := mmr.PeakHashes(store, sizes[2]-1)
	require.NoError(t, err)
	protected, err := canonicalReceiptCBOR.Marshal(map[int64]int64{
		checkpointLabelAlg: int64(signer.Algorithm()),
		checkpointLabelVDS: CheckpointVDSConsistency,
	})
	require.NoError(t, err)
	signature, err := signer.Sign(rand.Reader, SigStructure(protected, DetachedPayload(accumulator)))
	require.NoError(t, err)
	data, err := EncodeCheckpointReceipt(protected, proof, signature)
	require.NoError(t, err)
	receipt, err := DecodeCheckpointReceipt(data)
	require.NoError(t, err)

	verifier := newES256Verifier(t, &key.PublicKey)
	_, err = VerifyCheckpointReceipt(store, &receipt, verifier)
	require.ErrorIs(t, err, ErrSignedSizeMissing)
	_, err = VerifyCheckpointReceiptFromState(0, nil, &receipt, verifier)
	require.ErrorIs(t, err, ErrSignedSizeMissing)
}

// A protected header with no algorithm (label 1), or a non-integer under
// label 1, is rejected with a typed error before any signature check. The
// univocity contract's header walk rejects such a header with ClaimNotFound
// (1) or UnexpectedMajorType; without this check the off-chain low-s guard
// (verifyReceiptSignature) used to be silently skipped for exactly these
// headers, because ProtectedHeaderAlgorithm reported an error that nothing
// propagated (S-1).
func TestVerifyCheckpointReceiptRejectsInvalidAlgorithm(t *testing.T) {
	store, sizes := newFixtureMMR(t, 3)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer := mlcose.NewTestCoseSigner(t, *key)
	verifier := newES256Verifier(t, &key.PublicKey)

	proof, err := BuildConsistencyProof(store, 0, sizes[2])
	require.NoError(t, err)
	accumulator, err := mmr.PeakHashes(store, sizes[2]-1)
	require.NoError(t, err)

	sign := func(t *testing.T, protected []byte) CheckpointReceipt {
		t.Helper()
		signature, err := signer.Sign(rand.Reader, SigStructure(protected, DetachedPayload(accumulator)))
		require.NoError(t, err)
		signature = normalizeSignatureLowS(signer.Algorithm(), signature)
		data, err := EncodeCheckpointReceipt(protected, proof, signature)
		require.NoError(t, err)
		receipt, err := DecodeCheckpointReceipt(data)
		require.NoError(t, err)
		return receipt
	}

	for _, c := range []struct {
		name    string
		fields  map[int64]any
		wantErr error // nil means the receipt must verify
	}{
		{
			name: "alg is a well-formed integer",
			fields: map[int64]any{
				checkpointLabelAlg:       int64(signer.Algorithm()),
				checkpointLabelVDS:       CheckpointVDSConsistency,
				CheckpointLabelTreeSize2: sizes[2],
			},
			wantErr: nil,
		},
		{
			name: "alg is absent",
			fields: map[int64]any{
				checkpointLabelVDS:       CheckpointVDSConsistency,
				CheckpointLabelTreeSize2: sizes[2],
			},
			wantErr: ErrProtectedHeaderInvalid,
		},
		{
			name: "alg is a byte string",
			fields: map[int64]any{
				checkpointLabelAlg:       cbor.RawMessage{0x41, 0x26}, // h'26'
				checkpointLabelVDS:       CheckpointVDSConsistency,
				CheckpointLabelTreeSize2: sizes[2],
			},
			wantErr: ErrProtectedHeaderInvalid,
		},
		{
			name: "alg is a boolean",
			fields: map[int64]any{
				checkpointLabelAlg:       false,
				checkpointLabelVDS:       CheckpointVDSConsistency,
				CheckpointLabelTreeSize2: sizes[2],
			},
			wantErr: ErrProtectedHeaderInvalid,
		},
		{
			name: "alg is null",
			fields: map[int64]any{
				checkpointLabelAlg:       cbor.RawMessage{0xf6}, // null
				checkpointLabelVDS:       CheckpointVDSConsistency,
				CheckpointLabelTreeSize2: sizes[2],
			},
			wantErr: ErrProtectedHeaderInvalid,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			protected, err := canonicalReceiptCBOR.Marshal(c.fields)
			require.NoError(t, err)
			receipt := sign(t, protected)

			_, err = VerifyCheckpointReceipt(store, &receipt, verifier)
			if c.wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, c.wantErr)
			}

			_, err = VerifyCheckpointReceiptFromState(0, nil, &receipt, verifier)
			if c.wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, c.wantErr)
			}
		})
	}
}

// Third-party verification from a trusted state, with no log data: every
// (trusted, sealed) pair of the fixture verifies and yields the sealed
// accumulator.
func TestVerifyCheckpointReceiptFromStateVerifies(t *testing.T) {
	store, sizes := newFixtureMMR(t, 8)
	checked := 0
	for j, toSize := range sizes {
		froms := []uint64{0}
		froms = append(froms, sizes[:j]...)
		for _, fromSize := range froms {
			receipt, key := signFixtureCheckpoint(t, store, fromSize, toSize)
			var trusted [][]byte
			if fromSize > 0 {
				var err error
				trusted, err = mmr.PeakHashes(store, fromSize-1)
				require.NoError(t, err)
			}
			accumulator, err := VerifyCheckpointReceiptFromState(
				fromSize, trusted, &receipt, newES256Verifier(t, &key.PublicKey))
			require.NoError(t, err, "%d -> %d", fromSize, toSize)
			expected, err := mmr.PeakHashes(store, toSize-1)
			require.NoError(t, err)
			require.Equal(t, expected, accumulator)
			checked++
		}
	}
	require.Equal(t, 36, checked)
}

// Size substitution: the receipt signed for 7 -> 8 is presented as 7 -> 10
// (same paths, same right peaks, byte-identical signature) and a first
// checkpoint signed for size 1 is presented at the largest one-peak size.
// Both are rejected by the signed size comparison. These are the shapes
// where the fold alone does not bind the size (ADR-0066, context).
func TestVerifyCheckpointReceiptFromStateRejectsSizeSubstitution(t *testing.T) {
	store, sizes := newFixtureMMR(t, 8)
	require.Equal(t, []uint64{1, 3, 4, 7, 8, 10, 11, 15}, sizes)

	receipt, key := signFixtureCheckpoint(t, store, 7, 8)
	trusted, err := mmr.PeakHashes(store, 6)
	require.NoError(t, err)
	verifier := newES256Verifier(t, &key.PublicKey)
	_, err = VerifyCheckpointReceiptFromState(7, trusted, &receipt, verifier)
	require.NoError(t, err)

	receipt.Proofs[0].TreeSize2 = 10
	_, err = VerifyCheckpointReceiptFromState(7, trusted, &receipt, verifier)
	require.ErrorIs(t, err, ErrSignedSizeMismatch)

	first, key := signFixtureCheckpoint(t, store, 0, 1)
	verifier = newES256Verifier(t, &key.PublicKey)
	_, err = VerifyCheckpointReceiptFromState(0, nil, &first, verifier)
	require.NoError(t, err)

	first.Proofs[0].TreeSize2 = math.MaxUint64
	_, err = VerifyCheckpointReceiptFromState(0, nil, &first, verifier)
	require.ErrorIs(t, err, ErrSignedSizeMismatch)
}

// The trusted size is the verifier's, not the proof's: a receipt whose
// declared tree-size-1 differs from the trusted size does not apply to that
// state (ADR-0066 D5.4).
func TestVerifyCheckpointReceiptFromStateRequiresTrustedOrigin(t *testing.T) {
	store, sizes := newFixtureMMR(t, 8)
	receipt, key := signFixtureCheckpoint(t, store, sizes[3], sizes[6])
	trusted, err := mmr.PeakHashes(store, sizes[1]-1)
	require.NoError(t, err)

	_, err = VerifyCheckpointReceiptFromState(
		sizes[1], trusted, &receipt, newES256Verifier(t, &key.PublicKey))
	require.ErrorIs(t, err, ErrConsistencyProofCheck)
}

// The detached payload is a raw concatenation, so the same signed bytes split
// into entries at other boundaries would verify; every node must be the hash
// width.
func TestVerifyCheckpointReceiptFromStateRejectsResplitRightPeaks(t *testing.T) {
	store, sizes := newFixtureMMR(t, 8)
	receipt, key := signFixtureCheckpoint(t, store, 0, sizes[2])
	require.Len(t, receipt.Proofs[0].RightPeaks, 2)
	verifier := newES256Verifier(t, &key.PublicKey)

	flat := DetachedPayload(receipt.Proofs[0].RightPeaks)
	receipt.Proofs[0].RightPeaks = [][]byte{flat[:33], flat[33:]}
	_, err := VerifyCheckpointReceiptFromState(0, nil, &receipt, verifier)
	require.ErrorIs(t, err, ErrNodeWidth)

	folded, key := signFixtureCheckpoint(t, store, sizes[2], sizes[3])
	trusted, err := mmr.PeakHashes(store, sizes[2]-1)
	require.NoError(t, err)
	folded.Proofs[0].Paths[0][0] = folded.Proofs[0].Paths[0][0][:31]
	_, err = VerifyCheckpointReceiptFromState(sizes[2], trusted, &folded, newES256Verifier(t, &key.PublicKey))
	require.ErrorIs(t, err, ErrNodeWidth)
}

// Proof shape errors from the size-driven fold surface as consistency proof
// check failures with the mmr sentinel in the chain.
func TestVerifyCheckpointReceiptFromStateRejectsOffShapeProof(t *testing.T) {
	store, sizes := newFixtureMMR(t, 8)
	receipt, key := signFixtureCheckpoint(t, store, sizes[3], sizes[6])
	trusted, err := mmr.PeakHashes(store, sizes[3]-1)
	require.NoError(t, err)
	verifier := newES256Verifier(t, &key.PublicKey)

	// An emptied path where the sizes imply a longer one: for 4 -> 7 both
	// origin peaks fold under the one target peak (paths of length 1 and 2).
	folded, foldedKey := signFixtureCheckpoint(t, store, sizes[2], sizes[3])
	foldedTrusted, err := mmr.PeakHashes(store, sizes[2]-1)
	require.NoError(t, err)
	require.Len(t, folded.Proofs[0].Paths, 2)
	folded.Proofs[0].Paths[1] = [][]byte{}
	_, err = VerifyCheckpointReceiptFromState(
		sizes[2], foldedTrusted, &folded, newES256Verifier(t, &foldedKey.PublicKey))
	require.ErrorIs(t, err, ErrConsistencyProofCheck)
	require.ErrorIs(t, err, mmr.ErrConsistencyPathLength)

	// A surplus right peak.
	surplus := cloneReceipt(receipt)
	surplus.Proofs[0].RightPeaks = append(append([][]byte{}, receipt.Proofs[0].RightPeaks...), trusted[0])
	_, err = VerifyCheckpointReceiptFromState(sizes[3], trusted, &surplus, verifier)
	require.ErrorIs(t, err, ErrConsistencyProofCheck)

	// A replaced right peak changes the accumulator, so the signature fails.
	replaced := cloneReceipt(receipt)
	replaced.Proofs[0].RightPeaks = append([][]byte{}, receipt.Proofs[0].RightPeaks...)
	replaced.Proofs[0].RightPeaks[0] = trusted[0]
	_, err = VerifyCheckpointReceiptFromState(sizes[3], trusted, &replaced, verifier)
	require.ErrorIs(t, err, ErrSealVerifyFailed)
}
