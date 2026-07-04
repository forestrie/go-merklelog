package massifs

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func node(t *testing.T, lowHex string) []byte {
	t.Helper()
	var out [32]byte
	b, err := hex.DecodeString(lowHex)
	require.NoError(t, err)
	copy(out[32-len(b):], b)
	return out[:]
}

func TestDetachedPayloadIsRawConcat(t *testing.T) {
	p1 := node(t, "11")
	p2 := node(t, "22")
	require.Equal(t, append(append([]byte{}, p1...), p2...), DetachedPayload([][]byte{p1, p2}))
	require.Len(t, DetachedPayload([][]byte{p1, p2}), 64)
}

// SigStructure must match univocity cosecbor.buildSigStructure byte-for-byte.
func TestSigStructureMatchesContractCBOR(t *testing.T) {
	protected, err := hex.DecodeString("a1013a00010106")
	require.NoError(t, err)
	payload := node(t, "11") // 32-byte single-peak detached payload

	got := SigStructure(protected, payload)
	expected := "84" +
		"6a" + hex.EncodeToString([]byte("Signature1")) +
		"47" + "a1013a00010106" +
		"40" +
		"5820" + hex.EncodeToString(payload)
	require.Equal(t, expected, hex.EncodeToString(got))
}

func TestConsistencyProofRoundTrip(t *testing.T) {
	leaf1 := node(t, "11")
	leaf2 := node(t, "22")
	proof := ConsistencyProof{
		TreeSize1:  1,
		TreeSize2:  2,
		Paths:      [][][]byte{{leaf2}},
		RightPeaks: [][]byte{leaf2, leaf1},
	}
	encoded, err := EncodeConsistencyProof(proof)
	require.NoError(t, err)
	got, err := DecodeConsistencyProof(encoded)
	require.NoError(t, err)
	require.Equal(t, proof, got)
}

// The degenerate first-checkpoint proof (treeSize1 == 0, empty paths).
func TestConsistencyProofRoundTripFirstCheckpoint(t *testing.T) {
	leaf1 := node(t, "aa")
	proof := ConsistencyProof{
		TreeSize1:  0,
		TreeSize2:  1,
		Paths:      [][][]byte{},
		RightPeaks: [][]byte{leaf1},
	}
	encoded, err := EncodeConsistencyProof(proof)
	require.NoError(t, err)
	got, err := DecodeConsistencyProof(encoded)
	require.NoError(t, err)
	require.Equal(t, proof, got)
}

func TestCheckpointReceiptRoundTrip(t *testing.T) {
	leaf1 := node(t, "11")
	proof := ConsistencyProof{
		TreeSize1:  0,
		TreeSize2:  1,
		Paths:      [][][]byte{},
		RightPeaks: [][]byte{leaf1},
	}
	protected, err := hex.DecodeString("a1013a00010106")
	require.NoError(t, err)
	signature := make([]byte, 65)
	signature[0] = 0xAB

	encoded, err := EncodeCheckpointReceipt(protected, proof, signature)
	require.NoError(t, err)
	require.Equal(t, byte(0xd2), encoded[0],
		"receipt must be a tagged COSE_Sign1 (CBOR tag 18)")

	got, err := DecodeCheckpointReceipt(encoded)
	require.NoError(t, err)
	require.Equal(t, protected, got.ProtectedHeader)
	require.Equal(t, signature, got.Signature)
	require.Equal(t, proof, got.Proof)
}

// The detached payload a verifier reconstructs from a first-checkpoint proof
// (treeSize1 == 0) is exactly the right-peaks concatenation.
func TestFirstCheckpointDetachedPayload(t *testing.T) {
	leaf := sha256.Sum256([]byte("leaf"))
	proof := ConsistencyProof{
		TreeSize1:  0,
		TreeSize2:  1,
		Paths:      [][][]byte{},
		RightPeaks: [][]byte{leaf[:]},
	}
	require.Equal(t, leaf[:], DetachedPayload(proof.RightPeaks))
}
