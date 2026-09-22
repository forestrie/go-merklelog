package massifs

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/veraison/go-cose"
)

// ks256TestSigner is the cose.Signer side of AlgorithmKS256, for producing
// checkpoint material to verify. It lives in the test build because nothing
// in this repository seals with a KS256 key: the sealer signs ES256 and a
// KS256 root signs on chain or in a wallet. SignCheckpointReceipt takes any
// cose.Signer, so a KS256-rooted log can be sealed by supplying one.
type ks256TestSigner struct {
	key *secp256k1.PrivateKey
}

func (s *ks256TestSigner) Algorithm() cose.Algorithm { return AlgorithmKS256 }

// Sign returns r || s || v with v in {27, 28}, the form the KAT and the
// contract use. dcrec emits low-s and places the recovery code first.
func (s *ks256TestSigner) Sign(_ io.Reader, content []byte) ([]byte, error) {
	compact := dcrecdsa.SignCompact(s.key, keccak256(content), false)
	out := make([]byte, 65)
	copy(out, compact[1:])
	out[64] = compact[0]
	return out, nil
}

func ks256TestKey(t *testing.T, privHex string) (*ks256TestSigner, []byte) {
	t.Helper()
	b, err := hex.DecodeString(privHex)
	if err != nil {
		t.Fatal(err)
	}
	key := secp256k1.PrivKeyFromBytes(b)
	addr := KS256Address(key.PubKey())
	return &ks256TestSigner{key: key}, addr[:]
}

// ks256MalleateS returns (r, N-s). With the recovery id flipped that is the
// other valid encoding of the same signature, which ecrecover accepts;
// without, it recovers a different address.
func ks256MalleateS(t *testing.T, sig []byte, flipRecovery bool) []byte {
	t.Helper()
	var s secp256k1.ModNScalar
	if overflow := s.SetByteSlice(sig[32:64]); overflow {
		t.Fatal("signature s overflows the group order")
	}
	s.Negate()
	out := make([]byte, 65)
	copy(out, sig[:32])
	negated := s.Bytes()
	copy(out[32:64], negated[:])
	out[64] = sig[64]
	if flipRecovery {
		out[64] = 27 + (1 - (sig[64] - 27))
	}
	return out
}

// kat39FindReceipt returns the named row of the KAT's receipts list.
func kat39FindReceipt(t *testing.T, f *kat39File, name string) kat39Receipt {
	t.Helper()
	for _, row := range f.Receipts {
		if row.Name == name {
			return row
		}
	}
	t.Fatalf("KAT has no receipt row %q", name)
	return kat39Receipt{}
}

// kat39ProofOf returns the consistency proof a KAT row carries, by decoding
// the row's own receipt. Signing a fresh receipt over the same proof and
// accumulator exercises the encode side against the same geometry the
// vectors fix.
func kat39ProofOf(t *testing.T, row kat39Receipt) ConsistencyProof {
	t.Helper()
	receipt, err := DecodeCheckpointReceipt(kat39Bytes(t, row.ReceiptCborHex))
	if err != nil {
		t.Fatal(err)
	}
	return receipt.Proof
}

// A round trip through the package's own signing entry point: a KS256 root
// key seals a checkpoint and the verifier reads it back, with the
// accumulator recomputed from a trusted origin rather than taken from the
// receipt.
func TestKS256CheckpointRoundTrip(t *testing.T) {
	signer, addr := ks256TestKey(t,
		"ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	f := kat39Load(t)
	row := kat39FindReceipt(t, f, "ks256/7-to-15")
	target := kat39List(t, f.Tree.Accumulators[jsonKey(row.TreeSize2)].PeaksHex)
	origin := kat39List(t, f.Tree.Accumulators[jsonKey(row.TreeSize1)].PeaksHex)
	proof := kat39ProofOf(t, row)

	encoded, err := SignCheckpointReceipt(signer, proof, target)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := DecodeCheckpointReceipt(encoded)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewKS256Verifier(addr)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := VerifyCheckpointReceiptFromState(row.TreeSize1, origin, &receipt, verifier)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if !kat39Equal(acc, target) {
		t.Fatal("verified accumulator differs from the sealed one")
	}
}

func TestKS256VerifierRejections(t *testing.T) {
	signer, addr := ks256TestKey(t,
		"ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	f := kat39Load(t)
	row := kat39FindReceipt(t, f, "ks256/7-to-15")
	target := kat39List(t, f.Tree.Accumulators[jsonKey(row.TreeSize2)].PeaksHex)
	origin := kat39List(t, f.Tree.Accumulators[jsonKey(row.TreeSize1)].PeaksHex)
	proof := kat39ProofOf(t, row)

	encoded, err := SignCheckpointReceipt(signer, proof, target)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := DecodeCheckpointReceipt(encoded)
	if err != nil {
		t.Fatal(err)
	}
	sigStructure := SigStructure(receipt.ProtectedHeader, DetachedPayload(target))

	t.Run("a signature the other key produced is rejected", func(t *testing.T) {
		other, otherAddr := ks256TestKey(t,
			"59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")
		if bytes.Equal(addr, otherAddr) {
			t.Fatal("the two test keys are the same key")
		}
		otherSig, err := other.Sign(rand.Reader, sigStructure)
		if err != nil {
			t.Fatal(err)
		}
		v, err := NewKS256Verifier(addr)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Verify(sigStructure, otherSig); !errors.Is(err, ErrKS256SignerMismatch) {
			t.Fatalf("want ErrKS256SignerMismatch, got %v", err)
		}
	})

	t.Run("a verifier for the other address rejects the sealed receipt", func(t *testing.T) {
		_, otherAddr := ks256TestKey(t,
			"59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")
		v, err := NewKS256Verifier(otherAddr)
		if err != nil {
			t.Fatal(err)
		}
		_, err = VerifyCheckpointReceiptFromState(row.TreeSize1, origin, &receipt, v)
		if !errors.Is(err, ErrSealVerifyFailed) {
			t.Fatalf("want ErrSealVerifyFailed, got %v", err)
		}
	})

	t.Run("s negated without flipping the recovery id is rejected", func(t *testing.T) {
		// The naive malleation: (r, N-s) recovers a different key under the
		// unchanged recovery id, so both the precompile and this verifier
		// recover an address that is not the signer.
		malleated := ks256MalleateS(t, receipt.Signature, false)
		v, err := NewKS256Verifier(addr)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Verify(sigStructure, malleated); !errors.Is(err, ErrKS256SignerMismatch) {
			t.Fatalf("want ErrKS256SignerMismatch, got %v", err)
		}
	})

	t.Run("a recovery id outside 27 and 28 is rejected", func(t *testing.T) {
		for _, raw := range []byte{2, 3, 26, 29, 30, 31, 34, 255} {
			bad := make([]byte, 65)
			copy(bad, receipt.Signature)
			bad[64] = raw
			v, err := NewKS256Verifier(addr)
			if err != nil {
				t.Fatal(err)
			}
			err = v.Verify(sigStructure, bad)
			if !errors.Is(err, ErrKS256RecoveryID) && !errors.Is(err, ErrKS256SignerMismatch) {
				t.Fatalf("recovery id %d: want rejection, got %v", raw, err)
			}
		}
	})

	t.Run("a signature that is not 65 bytes is rejected", func(t *testing.T) {
		v, err := NewKS256Verifier(addr)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range []int{0, 64, 66} {
			if err := v.Verify(sigStructure, make([]byte, n)); !errors.Is(err, ErrKS256SignatureLength) {
				t.Fatalf("%d bytes: want ErrKS256SignatureLength, got %v", n, err)
			}
		}
	})

	t.Run("a signer that is not a 20-byte non-zero address is refused", func(t *testing.T) {
		for _, bad := range [][]byte{nil, make([]byte, 19), make([]byte, 20), make([]byte, 32)} {
			if _, err := NewKS256Verifier(bad); !errors.Is(err, ErrKS256SignerAddress) {
				t.Fatalf("%d bytes: want ErrKS256SignerAddress, got %v", len(bad), err)
			}
		}
	})

	t.Run("an ES256 verifier does not verify a KS256 receipt", func(t *testing.T) {
		_, err := VerifyCheckpointReceiptFromState(
			row.TreeSize1, origin, &receipt, kat39ES256Verifier(t, f))
		if !errors.Is(err, ErrSealVerifyFailed) {
			t.Fatalf("want ErrSealVerifyFailed, got %v", err)
		}
	})

	t.Run("a KS256 verifier does not verify an ES256 receipt", func(t *testing.T) {
		es256 := kat39FindReceipt(t, f, "es256/7-to-15")
		esReceipt, err := DecodeCheckpointReceipt(kat39Bytes(t, es256.ReceiptCborHex))
		if err != nil {
			t.Fatal(err)
		}
		v, err := NewKS256Verifier(addr)
		if err != nil {
			t.Fatal(err)
		}
		esOrigin := kat39List(t, f.Tree.Accumulators[jsonKey(es256.TreeSize1)].PeaksHex)
		_, err = VerifyCheckpointReceiptFromState(es256.TreeSize1, esOrigin, &esReceipt, v)
		if !errors.Is(err, ErrSealVerifyFailed) {
			t.Fatalf("want ErrSealVerifyFailed, got %v", err)
		}
	})
}

// The malleated form the chain accepts. ecrecover applies the frontier rule,
// so (r, N-s) with the recovery id flipped recovers the same signer and the
// contract accepts it; this verifier matches, and the pair the receipt binds
// is unchanged either way. Recorded as a property so a future low-s guard
// here cannot be added without deciding the chain's side of it too.
func TestKS256MalleatedSignatureMatchesTheChainsRule(t *testing.T) {
	signer, addr := ks256TestKey(t,
		"ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	f := kat39Load(t)
	row := kat39FindReceipt(t, f, "ks256/7-to-15")
	target := kat39List(t, f.Tree.Accumulators[jsonKey(row.TreeSize2)].PeaksHex)
	origin := kat39List(t, f.Tree.Accumulators[jsonKey(row.TreeSize1)].PeaksHex)

	encoded, err := SignCheckpointReceipt(signer, kat39ProofOf(t, row), target)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := DecodeCheckpointReceipt(encoded)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Signature = ks256MalleateS(t, receipt.Signature, true)

	v, err := NewKS256Verifier(addr)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := VerifyCheckpointReceiptFromState(row.TreeSize1, origin, &receipt, v)
	if err != nil {
		t.Fatalf("the malleated form the chain accepts was rejected: %v", err)
	}
	if !kat39Equal(acc, target) {
		t.Fatal("the malleated form bound a different accumulator")
	}
}
