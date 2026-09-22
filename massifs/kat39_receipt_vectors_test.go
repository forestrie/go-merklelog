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

const kat39VectorsSHA256 = "fb6bbde735537cfc97f83c52cfc4c609b4d1ed1474157910d7be0814456102c8"

type kat39Expect struct {
	Result   string `json:"result"`
	TreeSize uint64 `json:"tree_size_2"`
	Reason   string `json:"reason"`
	Class    string `json:"class"`
}

type kat39File struct {
	Tree struct {
		NodesHex     []string `json:"nodes_hex"`
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
	ReceiptChains    []kat39Chain   `json:"receipt_chains"`
}

// kat39Chain is a receipt relaying several consistency proofs under one
// signature (ADR-0066 D2). TrustedTreeSize1 is the size the verifier holds
// state for, which the first step must start at.
type kat39Chain struct {
	Name                 string   `json:"name"`
	Alg                  int64    `json:"alg"`
	TrustedTreeSize1     uint64   `json:"trusted_tree_size_1"`
	ReceiptCborHex       string   `json:"receipt_cbor_hex"`
	ConsistencyProofsHex []string `json:"consistency_proofs_hex"`
	Steps                []struct {
		TreeSize1 uint64 `json:"tree_size_1"`
		TreeSize2 uint64 `json:"tree_size_2"`
	} `json:"steps"`
	Expect kat39Expect `json:"expect"`
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

// TestKAT39ReceiptChains verifies the relayed-chain rows: a chain is folded
// step by step from the trusted origin and the signature is checked against
// the accumulator the last step reaches, so the accepted row must reach the
// tree's own accumulator for the signed size and each rejected row must fail
// for the reason it names.
func TestKAT39ReceiptChains(t *testing.T) {
	f := kat39Load(t)
	if len(f.ReceiptChains) == 0 {
		t.Fatal("the vectors carry no receipt_chains rows")
	}
	verifier := kat39ES256Verifier(t, f)
	require := func(cond bool, format string, args ...any) {
		t.Helper()
		if !cond {
			t.Errorf(format, args...)
		}
	}
	for _, row := range f.ReceiptChains {
		if row.Alg != int64(cose.AlgorithmES256) {
			continue // KS256 (secp256k1 + keccak) has no go-cose verifier
		}
		receipt, err := DecodeCheckpointReceipt(kat39Bytes(t, row.ReceiptCborHex))
		if err != nil {
			t.Fatalf("%s: decode: %v", row.Name, err)
		}
		require(len(receipt.Proofs) == len(row.Steps),
			"%s: %d proofs decoded, %d steps declared", row.Name, len(receipt.Proofs), len(row.Steps))
		for i, step := range row.Steps {
			require(receipt.Proofs[i].TreeSize1 == step.TreeSize1 &&
				receipt.Proofs[i].TreeSize2 == step.TreeSize2,
				"%s: step %d is %d -> %d, the row declares %d -> %d", row.Name, i,
				receipt.Proofs[i].TreeSize1, receipt.Proofs[i].TreeSize2,
				step.TreeSize1, step.TreeSize2)
		}

		origin := [][]byte{}
		if row.TrustedTreeSize1 > 0 {
			origin = kat39List(t, f.Tree.Accumulators[jsonKey(row.TrustedTreeSize1)].PeaksHex)
		}
		acc, err := VerifyCheckpointReceiptFromState(
			row.TrustedTreeSize1, origin, &receipt, verifier)
		switch row.Expect.Result {
		case "accept":
			if err != nil {
				t.Errorf("%s: verify: %v", row.Name, err)
				continue
			}
			target := kat39List(t, f.Tree.Accumulators[jsonKey(row.Expect.TreeSize)].PeaksHex)
			require(kat39Equal(acc, target),
				"%s: the folded accumulator differs from the tree's for size %d",
				row.Name, row.Expect.TreeSize)
		case "reject":
			if err == nil {
				t.Errorf("%s (%s): accepted", row.Name, row.Expect.Reason)
				continue
			}
			want := map[string]error{
				"chain_not_contiguous": ErrProofChainNotContiguous,
				"signed_size_mismatch": ErrSignedSizeMismatch,
			}[row.Expect.Reason]
			if want != nil && !errors.Is(err, want) {
				t.Errorf("%s: want %v, got %v", row.Name, want, err)
			}
		default:
			t.Errorf("%s: unknown result %s", row.Name, row.Expect.Result)
		}
	}
}

// TestKAT39ReceiptChainProofBytesMatchEncoder requires
// EncodeConsistencyProof(BuildConsistencyProof(...)) to reproduce the KAT's
// own consistency-proof bytes for each step of the accepted 1->3->4->7
// chain, byte for byte (GML15-F3). Step 1 (3->4) is the case that mattered:
// BuildConsistencyProof leaves a nil path for the one tree-size-1
// accumulator peak above the split, and the KAT vector (produced by the
// protocol reference, not this package) writes it as an empty array (`80`),
// not CBOR null (`f6`); the encoder must match that, not its own prior
// lenient behaviour.
func TestKAT39ReceiptChainProofBytesMatchEncoder(t *testing.T) {
	f := kat39Load(t)
	store := kat39Store(t)
	var row *kat39Chain
	for i := range f.ReceiptChains {
		if f.ReceiptChains[i].Name == "accept/chain-1-3-4-7" {
			row = &f.ReceiptChains[i]
			break
		}
	}
	if row == nil {
		t.Fatal("the vectors carry no accept/chain-1-3-4-7 row")
	}
	if len(row.ConsistencyProofsHex) != len(row.Steps) {
		t.Fatalf("row carries %d consistency proofs for %d steps",
			len(row.ConsistencyProofsHex), len(row.Steps))
	}
	for i, step := range row.Steps {
		proof, err := BuildConsistencyProof(store, step.TreeSize1, step.TreeSize2)
		if err != nil {
			t.Fatalf("step %d (%d->%d): build: %v", i, step.TreeSize1, step.TreeSize2, err)
		}
		got, err := EncodeConsistencyProof(proof)
		if err != nil {
			t.Fatalf("step %d (%d->%d): encode: %v", i, step.TreeSize1, step.TreeSize2, err)
		}
		want := kat39Bytes(t, row.ConsistencyProofsHex[i])
		if hex.EncodeToString(got) != hex.EncodeToString(want) {
			t.Errorf("step %d (%d->%d): encoded bytes differ from the KAT vector\n got=%x\nwant=%x",
				i, step.TreeSize1, step.TreeSize2, got, want)
		}
	}
}
