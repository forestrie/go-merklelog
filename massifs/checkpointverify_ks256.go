package massifs

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/veraison/go-cose"
	"golang.org/x/crypto/sha3"
)

// AlgorithmKS256 is the private-use COSE algorithm for secp256k1 ECDSA over
// keccak-256 of the Sig_structure, in Ethereum's recoverable 65-byte form
// (r || s || v). The univocity contract accepts it on a checkpoint receipt
// (cosecbor/constants.sol ALG_KS256, _Univocity.sol
// _verifyCheckpointSignatureKS256), so every replica must be able to
// re-verify one; see KS256Verifier.
//
// It is NOT the registered ES256K (-47): that is secp256k1 over SHA-256 and
// is not recoverable, so an ES256K verifier cannot read a KS256 signature and
// a KS256 verifier must not be offered an ES256K one.
const AlgorithmKS256 cose.Algorithm = -65799

var (
	// ErrKS256SignerAddress is returned when a KS256 verifier is constructed
	// with something other than a 20-byte non-zero Ethereum address. The
	// contract rejects a zero recovered address unconditionally, so a zero
	// expected address can never be the right answer.
	ErrKS256SignerAddress = errors.New("a KS256 signer must be a 20-byte non-zero address")
	// ErrKS256SignatureLength is returned for a signature that is not the
	// 65-byte r || s || v form (cosecbor.sol InvalidSignatureLength(65, n)).
	ErrKS256SignatureLength = errors.New("a KS256 signature must be 65 bytes")
	// ErrKS256RecoveryID is returned when the recovery byte does not
	// normalise to 27 or 28. The contract raises v by 27 when it is below 27
	// and then hands it to ecrecover, which accepts only 27 and 28; anything
	// else recovers the zero address and fails.
	ErrKS256RecoveryID = errors.New("a KS256 recovery id must normalise to 27 or 28")
	// ErrKS256SignerMismatch is returned when the recovered address is not
	// the expected signer.
	ErrKS256SignerMismatch = errors.New("the KS256 signature recovers a different address")
	// ErrKS256ContractSigner is returned when the signer is known to carry
	// contract code. The contract then verifies through ERC-1271 rather than
	// ecrecover, which is a call into chain state that no offline verifier
	// can reproduce; supply an ERC1271Verifier to bridge it.
	ErrKS256ContractSigner = errors.New("the KS256 signer carries contract code; ERC-1271 verification needs chain access")
)

// ERC1271Verifier bridges the contract-wallet half of the contract's KS256
// rule: cosecbor.sol verifyKS256Raw takes the ERC-1271 path whenever the
// expected signer address has code, and the EOA ecrecover path otherwise.
// Deciding which, and evaluating isValidSignature, both need chain state, so
// they are the caller's to provide. The shape matches arbor's
// delegationcert.ERC1271Verifier so one adapter serves both.
type ERC1271Verifier interface {
	// HasCode reports whether the 20-byte address has contract code.
	HasCode(ctx context.Context, addr []byte) (bool, error)
	// IsValidSignature returns nil when the contract at addr accepts sig
	// over hash under ERC-1271.
	IsValidSignature(ctx context.Context, addr, hash, sig []byte) error
}

// KS256Verifier is the cose.Verifier VerifyCheckpointReceipt and
// VerifyCheckpointReceiptFromState take for a KS256 checkpoint receipt. It
// performs the same signature verification as the contract's verifyKS256Raw:
//
//	keccak256(Sig_structure) -> ecrecover(hash, v, r, s) == signer
//
// where Sig_structure is the bytes SigStructure builds and the caller has
// already supplied as Verify's content, and the signature is r || s || v with
// v normalised the way cosecbor.sol verifyKS256Raw normalises it.
//
// Nothing here is new cryptography. It is the same recovery arbor performs
// for delegation certificates (services/pkgs/delegationcert
// verify_certificate_ks256.go) and canopy-api performs for grants
// (grant/ks256-verify.ts), expressed against the cose.Verifier interface
// this package's checkpoint entry points already accept.
//
// Malleability is deliberately not filtered. The ecrecover precompile
// applies the frontier rule (go-ethereum ValidateSignatureValues with
// homestead false), so it accepts s in the full range [1, N-1], and a
// checkpoint carrying (r, N-s) with the recovery id flipped is one the chain
// accepts. Rejecting it here would recreate the divergence this verifier
// exists to close, in the opposite direction. A receipt malleated that way is
// a different byte string binding the identical (tree-size-2, accumulator)
// pair, so it gains nothing; the ES256 high-s guard in verifyReceiptSignature
// is a different case, where the contract is the stricter side.
type KS256Verifier struct {
	signer  [20]byte
	erc1271 ERC1271Verifier
}

// KS256VerifierOption configures a KS256Verifier.
type KS256VerifierOption func(*KS256Verifier)

// WithERC1271 supplies the chain-state hooks the contract-wallet signer case
// needs. Without it a signer carrying code cannot be decided offline, and
// Verify reports ErrKS256ContractSigner only if the caller has established
// that separately; an EOA signer needs no hooks at all.
func WithERC1271(erc1271 ERC1271Verifier) KS256VerifierOption {
	return func(v *KS256Verifier) { v.erc1271 = erc1271 }
}

// NewKS256Verifier returns a cose.Verifier for KS256 checkpoint receipts
// signed by the 20-byte Ethereum address signer. This is the address the
// contract holds as the log's root key (_Univocity.sol
// _decodeLogRootKeyKS256) or as the bootstrap signer.
func NewKS256Verifier(signer []byte, opts ...KS256VerifierOption) (*KS256Verifier, error) {
	if len(signer) != 20 || bytes.Equal(signer, make([]byte, 20)) {
		return nil, fmt.Errorf("%w: got %d bytes", ErrKS256SignerAddress, len(signer))
	}
	v := &KS256Verifier{}
	copy(v.signer[:], signer)
	for _, opt := range opts {
		opt(v)
	}
	return v, nil
}

// Algorithm returns AlgorithmKS256, which verifyReceiptSignature requires to
// equal the receipt's signed protected-header algorithm.
func (v *KS256Verifier) Algorithm() cose.Algorithm { return AlgorithmKS256 }

// Signer returns the 20-byte address this verifier accepts.
func (v *KS256Verifier) Signer() []byte {
	out := make([]byte, 20)
	copy(out, v.signer[:])
	return out
}

// Verify checks signature over content, where content is the full
// Sig_structure bytes and NOT a digest: the cose.Verifier contract hands the
// verifier the unhashed to-be-signed bytes and leaves the digest to the
// algorithm, which is why a keccak-256 algorithm needs no change to go-cose.
func (v *KS256Verifier) Verify(content, signature []byte) error {
	hash := keccak256(content)

	if v.erc1271 != nil {
		ctx := context.Background()
		hasCode, err := v.erc1271.HasCode(ctx, v.signer[:])
		if err != nil {
			return fmt.Errorf("ks256 erc1271 code check: %w", err)
		}
		if hasCode {
			if err := v.erc1271.IsValidSignature(ctx, v.signer[:], hash, signature); err != nil {
				return fmt.Errorf("ks256 erc1271 rejected the signature: %w", err)
			}
			return nil
		}
	}

	recovered, err := RecoverKS256Signer(hash, signature)
	if err != nil {
		return err
	}
	if recovered != v.signer {
		return fmt.Errorf("%w: recovered %x, expected %x",
			ErrKS256SignerMismatch, recovered, v.signer)
	}
	return nil
}

// RecoverKS256Signer recovers the 20-byte Ethereum address that produced a
// 65-byte r || s || v signature over the 32-byte hash, applying the same
// recovery-id normalisation the contract applies.
func RecoverKS256Signer(hash, signature []byte) ([20]byte, error) {
	var addr [20]byte
	if len(signature) != 65 {
		return addr, fmt.Errorf("%w: got %d", ErrKS256SignatureLength, len(signature))
	}
	// cosecbor.sol verifyKS256Raw: `if (v < 27) v += 27`, then ecrecover,
	// which accepts 27 and 28 only. 29 and 30 are valid dcrec recovery codes
	// and 31..34 are its compressed-pubkey variants, so the range has to be
	// closed here or this verifier would accept signatures the chain does
	// not.
	recoveryID := signature[64]
	if recoveryID < 27 {
		recoveryID += 27
	}
	if recoveryID != 27 && recoveryID != 28 {
		return addr, fmt.Errorf("%w: got %d", ErrKS256RecoveryID, signature[64])
	}
	// dcrec's compact form puts the recovery code first; Ethereum's puts it
	// last.
	compact := make([]byte, 65)
	compact[0] = recoveryID
	copy(compact[1:], signature[:64])
	pub, _, err := dcrecdsa.RecoverCompact(compact, hash)
	if err != nil {
		return addr, fmt.Errorf("%w: %w", ErrKS256SignerMismatch, err)
	}
	return KS256Address(pub), nil
}

// KS256Address returns the Ethereum address of a secp256k1 public key: the
// low 20 bytes of keccak256 over the uncompressed encoding with its 0x04
// prefix removed.
func KS256Address(pub *secp256k1.PublicKey) [20]byte {
	var addr [20]byte
	sum := keccak256(pub.SerializeUncompressed()[1:])
	copy(addr[:], sum[12:])
	return addr
}

// keccak256 is the original Keccak padding Ethereum uses, which is not the
// FIPS-202 SHA3-256 the standard library provides.
func keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}
