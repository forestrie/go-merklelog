package massifs

// Consumes the cross-language checkpoint-receipt KAT (forestrie/protocol
// vectors/fixtures/checkpoint-receipt-kat39.json). The copy under testdata/
// must match the protocol repository's pinned sum; every row must pass. A
// row this package cannot pass is a defect here or in the rule, never a
// reason to edit the copy.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"testing"

	"github.com/forestrie/go-merklelog/mmr"
	"github.com/veraison/go-cose"
)

const kat39VectorsSHA256 = "391d203b99b8dc41226694edee4eab3da3f1aa9bc651d13408d1a21b0986a8b8"

type kat39Expect struct {
	Result   string `json:"result"`
	TreeSize uint64 `json:"tree_size_2"`
	Reason   string `json:"reason"`
	Class    string `json:"class"`
}

type kat39File struct {
	Tree struct {
		Accumulators map[string]struct {
			PeaksHex []string `json:"peaks_hex"`
		} `json:"accumulators"`
	} `json:"tree"`
	ConsistencyPairs []struct {
		Name               string     `json:"name"`
		TreeSize1          uint64     `json:"tree_size_1"`
		TreeSize2          uint64     `json:"tree_size_2"`
		AccumulatorFromHex []string   `json:"accumulator_from_hex"`
		PathsHex           [][]string `json:"paths_hex"`
		RootsHex           []string   `json:"roots_hex"`
		RightPeakCount     int        `json:"right_peak_count"`
		AccumulatorToHex   []string   `json:"accumulator_to_hex"`
	} `json:"consistency_pairs"`
	ConsistencyNegatives []struct {
		Name               string      `json:"name"`
		TreeSize1          uint64      `json:"tree_size_1"`
		TreeSize2          uint64      `json:"tree_size_2"`
		TrustedTreeSize1   uint64      `json:"trusted_tree_size_1"`
		AccumulatorFromHex []string    `json:"accumulator_from_hex"`
		PathsHex           [][]string  `json:"paths_hex"`
		RightPeaksHex      []string    `json:"right_peaks_hex"`
		Expect             kat39Expect `json:"expect"`
	} `json:"consistency_negatives"`
	ProtectedHeaders []struct {
		Name   string      `json:"name"`
		Hex    string      `json:"hex"`
		Expect kat39Expect `json:"expect"`
	} `json:"protected_headers"`
	Keys struct {
		ES256 struct {
			PublicXHex string `json:"public_x_hex"`
			PublicYHex string `json:"public_y_hex"`
		} `json:"es256"`
	} `json:"keys"`
	Receipts         []kat39Receipt `json:"receipts"`
	ReceiptNegatives []kat39Receipt `json:"receipt_negatives"`
}

type kat39Receipt struct {
	Name               string      `json:"name"`
	Alg                int64       `json:"alg"`
	TreeSize1          uint64      `json:"tree_size_1"`
	TreeSize2          uint64      `json:"tree_size_2"`
	ProtectedHeaderHex string      `json:"protected_header_hex"`
	DetachedPayloadHex string      `json:"detached_payload_hex"`
	SigStructureHex    string      `json:"sig_structure_hex"`
	SignatureHex       string      `json:"signature_hex"`
	ReceiptCborHex     string      `json:"receipt_cbor_hex"`
	Expect             kat39Expect `json:"expect"`
}

func kat39Load(t *testing.T) *kat39File {
	t.Helper()
	data, err := os.ReadFile("testdata/checkpoint-receipt-kat39.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != kat39VectorsSHA256 {
		t.Fatalf("testdata copy differs from the protocol pin: %s", got)
	}
	var f kat39File
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return &f
}

func kat39Bytes(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func kat39List(t *testing.T, hs []string) [][]byte {
	out := make([][]byte, len(hs))
	for i, h := range hs {
		out[i] = kat39Bytes(t, h)
	}
	return out
}

func kat39Paths(t *testing.T, ps [][]string) [][][]byte {
	out := make([][][]byte, len(ps))
	for i, p := range ps {
		out[i] = kat39List(t, p)
	}
	return out
}

func kat39Equal(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if hex.EncodeToString(a[i]) != hex.EncodeToString(b[i]) {
			return false
		}
	}
	return true
}

func TestKAT39ConsistencyPairs(t *testing.T) {
	f := kat39Load(t)
	for _, row := range f.ConsistencyPairs {
		roots, right, err := mmr.ConsistentRootsForSizes(
			sha256.New(), row.TreeSize1, row.TreeSize2,
			kat39List(t, row.AccumulatorFromHex), kat39Paths(t, row.PathsHex))
		if err != nil {
			t.Fatalf("%s: %v", row.Name, err)
		}
		if !kat39Equal(roots, kat39List(t, row.RootsHex)) || right != row.RightPeakCount {
			t.Fatalf("%s: roots or right-peak count differ", row.Name)
		}
		acc := append(append([][]byte{}, roots...), kat39List(t, row.AccumulatorToHex)[len(roots):]...)
		if !kat39Equal(acc, kat39List(t, f.Tree.Accumulators[jsonKey(row.TreeSize2)].PeaksHex)) {
			t.Fatalf("%s: accumulator does not match the tree", row.Name)
		}
	}
}

func jsonKey(n uint64) string { return big.NewInt(0).SetUint64(n).String() }

func TestKAT39ConsistencyNegatives(t *testing.T) {
	f := kat39Load(t)
	for _, row := range f.ConsistencyNegatives {
		if row.Expect.Class == "base_mismatch" {
			if row.TreeSize1 == row.TrustedTreeSize1 {
				t.Fatalf("%s: vector does not exhibit a base mismatch", row.Name)
			}
			continue // the comparison is made by the verifier before folding
		}
		_, right, err := mmr.ConsistentRootsForSizes(
			sha256.New(), row.TreeSize1, row.TreeSize2,
			kat39List(t, row.AccumulatorFromHex), kat39Paths(t, row.PathsHex))
		switch row.Expect.Class {
		case "right_peak_count_mismatch":
			if err != nil {
				t.Fatalf("%s: fold rejected before the right-peak check: %v", row.Name, err)
			}
			if right == len(row.RightPeaksHex) {
				t.Fatalf("%s: right-peak count %d matches the surplus supply", row.Name, right)
			}
		default:
			want := map[string]error{
				"size_must_increase":   mmr.ErrSizesNotIncreasing,
				"incomplete_tree_size": mmr.ErrIncompleteTreeSize,
				"peak_count_mismatch":  mmr.ErrConsistencyPeakCount,
				"path_length_mismatch": mmr.ErrConsistencyPathLength,
				"root_mismatch":        mmr.ErrConsistencyRootMismatch,
			}[row.Expect.Class]
			if want == nil {
				t.Fatalf("%s: unknown class %s", row.Name, row.Expect.Class)
			}
			if !errors.Is(err, want) {
				t.Fatalf("%s: want %v, got %v", row.Name, want, err)
			}
		}
	}
}

func TestKAT39ProtectedHeaders(t *testing.T) {
	f := kat39Load(t)
	for _, row := range f.ProtectedHeaders {
		size, err := ProtectedHeaderTreeSize(kat39Bytes(t, row.Hex))
		switch row.Expect.Result {
		case "accept":
			if err != nil || size != row.Expect.TreeSize {
				t.Errorf("%s: want size %d, got %d, err %v", row.Name, row.Expect.TreeSize, size, err)
			}
		case "absent":
			if !errors.Is(err, ErrSignedSizeMissing) {
				t.Errorf("%s: want ErrSignedSizeMissing, got %v", row.Name, err)
			}
		case "reject":
			if err == nil || errors.Is(err, ErrSignedSizeMissing) {
				t.Errorf("%s (%s): want rejection, got size %d err %v", row.Name, row.Expect.Reason, size, err)
			}
		}
	}
}

func kat39ES256Verifier(t *testing.T, f *kat39File) cose.Verifier {
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(),
		X: new(big.Int).SetBytes(kat39Bytes(t, f.Keys.ES256.PublicXHex)),
		Y: new(big.Int).SetBytes(kat39Bytes(t, f.Keys.ES256.PublicYHex))}
	v, err := cose.NewVerifier(cose.AlgorithmES256, pub)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestKAT39Receipts(t *testing.T) {
	f := kat39Load(t)
	verifier := kat39ES256Verifier(t, f)
	for _, row := range f.Receipts {
		if row.Alg != int64(cose.AlgorithmES256) {
			continue // KS256 (secp256k1 + keccak) has no go-cose verifier; covered by univocity and canopy
		}
		receipt, err := DecodeCheckpointReceipt(kat39Bytes(t, row.ReceiptCborHex))
		if err != nil {
			t.Fatalf("%s: decode: %v", row.Name, err)
		}
		if hex.EncodeToString(receipt.ProtectedHeader) != row.ProtectedHeaderHex ||
			hex.EncodeToString(receipt.Signature) != row.SignatureHex {
			t.Fatalf("%s: decoded header or signature differ", row.Name)
		}
		target := kat39List(t, f.Tree.Accumulators[jsonKey(row.TreeSize2)].PeaksHex)
		if hex.EncodeToString(DetachedPayload(target)) != row.DetachedPayloadHex {
			t.Fatalf("%s: detached payload differs", row.Name)
		}
		if hex.EncodeToString(SigStructure(receipt.ProtectedHeader, DetachedPayload(target))) != row.SigStructureHex {
			t.Fatalf("%s: Sig_structure differs", row.Name)
		}
		origin := [][]byte{}
		if row.TreeSize1 > 0 {
			origin = kat39List(t, f.Tree.Accumulators[jsonKey(row.TreeSize1)].PeaksHex)
		}
		acc, err := VerifyCheckpointReceiptFromState(row.TreeSize1, origin, &receipt, verifier)
		if err != nil {
			t.Fatalf("%s: verify: %v", row.Name, err)
		}
		if !kat39Equal(acc, target) {
			t.Fatalf("%s: verified accumulator differs from the tree", row.Name)
		}
	}
}

func TestKAT39ReceiptNegatives(t *testing.T) {
	f := kat39Load(t)
	verifier := kat39ES256Verifier(t, f)
	for _, row := range f.ReceiptNegatives {
		receipt, err := DecodeCheckpointReceipt(kat39Bytes(t, row.ReceiptCborHex))
		if err != nil {
			t.Fatalf("%s: decode: %v", row.Name, err)
		}
		origin := kat39List(t, f.Tree.Accumulators[jsonKey(row.TreeSize1)].PeaksHex)
		_, err = VerifyCheckpointReceiptFromState(row.TreeSize1, origin, &receipt, verifier)
		if err == nil {
			t.Errorf("%s (%s): accepted", row.Name, row.Expect.Reason)
			continue
		}
		want := map[string]error{
			"signed_size_mismatch": ErrSignedSizeMismatch,
			"signed_size_missing":  ErrSignedSizeMissing,
			"signature_invalid":    ErrSealVerifyFailed,
			"signature_malleable":  ErrSealVerifyFailed,
		}[row.Expect.Reason]
		if want != nil && !errors.Is(err, want) {
			t.Errorf("%s: want %v, got %v", row.Name, want, err)
		}
	}
}
