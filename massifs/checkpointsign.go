package massifs

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math"
	"math/big"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

var (
	p256N     = elliptic.P256().Params().N
	p256HalfN = new(big.Int).Rsh(elliptic.P256().Params().N, 1)
)

// normalizeSignatureLowS returns the low-s form of an ES256 signature
// (r || s, 64 bytes): (r, N-s) verifies for exactly the same digest and key.
// ECDSA backends (crypto/ecdsa, KMS) make no low-s guarantee, while the
// univocity on-chain P256 verifier rejects malleable high-s signatures, so
// checkpoint material is always emitted in low-s form. Non-ES256 signatures
// are returned unchanged.
func normalizeSignatureLowS(alg cose.Algorithm, sig []byte) []byte {
	if alg != cose.AlgorithmES256 || len(sig) != 64 {
		return sig
	}
	s := new(big.Int).SetBytes(sig[32:])
	if s.Cmp(p256HalfN) <= 0 {
		return sig
	}
	s.Sub(p256N, s)
	out := make([]byte, 64)
	copy(out, sig[:32])
	s.FillBytes(out[32:])
	return out
}

// CheckpointSignOption configures optional checkpoint receipt content.
type CheckpointSignOption func(*checkpointSignOptions)

type checkpointSignOptions struct {
	peakReceipts bool
	kid          []byte
	extras       map[int64]cbor.RawMessage
}

// WithPeakReceipts requests one pre-signed peak inclusion receipt per
// accumulator peak, carried under the private SealPeakReceiptsLabel in the
// checkpoint's unprotected header. kid identifies the signing key in each
// receipt's protected header (label 4); it may be nil. See SignPeakReceipts.
func WithPeakReceipts(kid []byte) CheckpointSignOption {
	return func(o *checkpointSignOptions) {
		o.peakReceipts = true
		o.kid = kid
	}
}

// WithUnprotectedExtras attaches additional unprotected header labels to the
// encoded checkpoint (delegation material, certificates). The values are
// carried verbatim and do not affect the checkpoint signature.
func WithUnprotectedExtras(extras map[int64]cbor.RawMessage) CheckpointSignOption {
	return func(o *checkpointSignOptions) {
		o.extras = extras
	}
}

// SignCheckpointReceipt produces a format-v3 checkpoint object carrying a
// single consistency proof. See SignCheckpointReceiptChain, of which this is
// the one-proof case.
func SignCheckpointReceipt(
	signer cose.Signer, proof ConsistencyProof, accumulator [][]byte,
	opts ...CheckpointSignOption,
) ([]byte, error) {
	return SignCheckpointReceiptChain(
		signer, []ConsistencyProof{proof}, accumulator, opts...)
}

// SignCheckpointReceiptChain produces a format-v3 checkpoint object
// (draft-bryce COSE Receipt of Consistency, ADR-0046): it signs the detached
// raw-concat payload of the accumulator for the seal's mmr size, over the
// COSE Sig_structure the univocity contract verifies, and encodes the receipt
// with the consistency proofs in the unprotected header.
//
// proofs is the chain in fold order, one per sealed step, and accumulator is
// the accumulator of the last proof's tree-size-2 - the size the protected
// header carries, and the only size the signature binds (ADR-0066 D2). The
// intermediate sizes are checked against the verifier's own trusted state as
// the chain is folded, so they need no signature of their own, and a
// publisher may re-base a step under the original signature.
//
// The signer is the log's COSE signer (the sealer's delegated ES256/KMS key,
// or a root key). The protected header is
// {1: alg, 395: vds=3, -65933: tree-size-2}: the contract reads the algorithm
// from label 1 and derives the same detached payload from the proof, so the
// signature verifies on-chain, and tree-size-2, the size the accumulator was
// read at, is signed alongside it (ADR-0066). Without that the same signed
// accumulator is accepted at every size with the same peak count. The
// contract and every off-chain verifier require the signed tree-size-2 to
// equal the declared one; tree-size-1 is unsigned prover context and a
// verifier takes the origin from state it already trusts. The delegation
// proof and CWT claims are added by the sealer/consumer layers as needed.
//
// With WithPeakReceipts, one additional detached-payload COSE_Sign1 is signed
// per accumulator peak and carried in the unprotected header, enabling any
// holder of the checkpoint and replicated log data to mint inclusion receipts
// without the signing key.
func SignCheckpointReceiptChain(
	signer cose.Signer, proofs []ConsistencyProof, accumulator [][]byte,
	opts ...CheckpointSignOption,
) ([]byte, error) {
	if len(proofs) == 0 {
		return nil, ErrProofChainEmpty
	}
	var options checkpointSignOptions
	for _, opt := range opts {
		opt(&options)
	}

	protected, err := canonicalReceiptCBOR.Marshal(map[int64]any{
		checkpointLabelAlg:       int64(signer.Algorithm()),
		checkpointLabelVDS:       CheckpointVDSConsistency,
		CheckpointLabelTreeSize2: proofs[len(proofs)-1].TreeSize2,
	})
	if err != nil {
		return nil, fmt.Errorf("encode protected header: %w", err)
	}

	// The signature is over Sig_structure(protected, detached payload); the
	// COSE signer applies the algorithm's hash before signing, matching the
	// contract's sha256/keccak of the same Sig_structure bytes.
	sigStructure := SigStructure(protected, DetachedPayload(accumulator))
	signature, err := signer.Sign(rand.Reader, sigStructure)
	if err != nil {
		return nil, fmt.Errorf("sign checkpoint receipt: %w", err)
	}
	signature = normalizeSignatureLowS(signer.Algorithm(), signature)

	extras := map[int64]cbor.RawMessage{}
	for label, value := range options.extras {
		extras[label] = value
	}
	if options.peakReceipts {
		receipts, err := SignPeakReceipts(signer, options.kid, accumulator)
		if err != nil {
			return nil, err
		}
		encoded, err := canonicalReceiptCBOR.Marshal(receipts)
		if err != nil {
			return nil, fmt.Errorf("encode peak receipts: %w", err)
		}
		extras[SealPeakReceiptsLabel] = encoded
	}
	if len(extras) == 0 {
		return EncodeCheckpointReceiptChain(protected, proofs, signature)
	}
	return EncodeCheckpointReceiptChain(protected, proofs, signature, extras)
}

// SignPeakReceipts signs one peak inclusion receipt per accumulator peak: a
// tagged COSE_Sign1 with a detached payload (the peak node value, per the
// draft-bryce Receipt of Inclusion) and an empty unprotected header. Proofs
// of inclusion for individual entries are attached to the unprotected header
// on demand, trustlessly, by whoever holds the log data (see NewReceipt).
//
// It is a specific property of MMR based logs that inclusion proofs always
// lead to an accumulator peak, so signing each peak once pre-signs a receipt
// for every possible inclusion proof in the sealed state. And due to the Low
// Update Frequency property (https://eprint.iacr.org/2015/718.pdf) the signed
// peak for any element changes less and less frequently (log base 2) as the
// log grows, so old receipts remain useful.
//
// The protected header is slim - {1: alg, 395: vds, 4: kid} - carrying no key
// material; verifiers obtain the log's public key the same way as for the
// checkpoint itself. kid may be nil, in which case label 4 is omitted.
func SignPeakReceipts(signer cose.Signer, kid []byte, accumulator [][]byte) ([][]byte, error) {
	headers := map[int64]any{
		checkpointLabelAlg: int64(signer.Algorithm()),
		checkpointLabelVDS: CheckpointVDSConsistency,
	}
	if len(kid) > 0 {
		headers[int64(cose.HeaderLabelKeyID)] = kid
	}
	protected, err := canonicalReceiptCBOR.Marshal(headers)
	if err != nil {
		return nil, fmt.Errorf("encode peak receipt protected header: %w", err)
	}

	receipts := make([][]byte, len(accumulator))
	for i, peak := range accumulator {
		signature, err := signer.Sign(rand.Reader, SigStructure(protected, peak))
		if err != nil {
			return nil, fmt.Errorf("sign peak receipt %d: %w", i, err)
		}
		signature = normalizeSignatureLowS(signer.Algorithm(), signature)
		sign1 := []any{protected, map[int64]cbor.RawMessage{}, nil, signature}
		receipts[i], err = canonicalReceiptCBOR.Marshal(cbor.Tag{Number: 18, Content: sign1})
		if err != nil {
			return nil, fmt.Errorf("encode peak receipt %d: %w", i, err)
		}
	}
	return receipts, nil
}

// strictHeaderCBOR decodes protected headers: duplicate keys, indefinite
// lengths and tags are rejected, so that the signed bytes have exactly one
// reading. A canonical parser (the univocity contract's) and this reader
// must agree on every accepted header.
var strictHeaderCBOR cbor.DecMode

func init() {
	dm, err := cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
		IndefLength: cbor.IndefLengthForbidden,
		TagsMd:      cbor.TagsForbidden,
	}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("massifs: strict cbor mode: %v", err))
	}
	strictHeaderCBOR = dm
}

// decodeProtectedHeader decodes a checkpoint receipt's protected header
// strictly and requires it to be in canonical form: re-encoding the decoded
// map must reproduce the input bytes, so a non-canonical integer encoding or
// key order is rejected rather than read.
func decodeProtectedHeader(protectedHeader []byte) (map[int64]any, error) {
	var m map[int64]any
	if err := strictHeaderCBOR.Unmarshal(protectedHeader, &m); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProtectedHeaderInvalid, err)
	}
	canonical, err := canonicalReceiptCBOR.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProtectedHeaderInvalid, err)
	}
	if !bytes.Equal(canonical, protectedHeader) {
		return nil, fmt.Errorf("%w: not canonical cbor", ErrProtectedHeaderInvalid)
	}
	// ADR-0066 D9: a label the verifier does not read may carry only an
	// integer, a byte string, a text string, false/true/null or a float
	// (shortest form, already enforced by the canonical re-encode above).
	// Containers, tags, undefined and other simple values are rejected so
	// that every verifier agrees on which headers are valid.
	for label, v := range m {
		switch v.(type) {
		case int64, uint64, []byte, string, bool, nil, float64, float32:
		default:
			return nil, fmt.Errorf("%w: label %d carries a value type the profile excludes (%T)",
				ErrProtectedHeaderInvalid, label, v)
		}
	}
	return m, nil
}

// ProtectedHeaderAlgorithm reads the COSE algorithm from a checkpoint receipt's
// protected header (label 1), as the contract does. Useful for consumers
// selecting a verification path.
func ProtectedHeaderAlgorithm(protectedHeader []byte) (int64, error) {
	m, err := decodeProtectedHeader(protectedHeader)
	if err != nil {
		return 0, err
	}
	v, ok := m[checkpointLabelAlg]
	if !ok {
		return 0, fmt.Errorf("%w: protected header has no algorithm (label %d)",
			ErrProtectedHeaderInvalid, checkpointLabelAlg)
	}
	switch alg := v.(type) {
	case int64:
		return alg, nil
	case uint64:
		if alg > math.MaxInt64 {
			return 0, fmt.Errorf("%w: algorithm %d out of range", ErrProtectedHeaderInvalid, alg)
		}
		return int64(alg), nil
	default:
		return 0, fmt.Errorf("%w: algorithm is not an integer", ErrProtectedHeaderInvalid)
	}
}

// ProtectedHeaderTreeSize reads the signed tree-size-2 from a checkpoint
// receipt's protected header (label CheckpointLabelTreeSize2, ADR-0066). It
// returns ErrSignedSizeMissing when the label is absent, which is the case
// for any header signed before ADR-0066 (the {1, 395} form), and
// ErrProtectedHeaderInvalid when the header is not canonical or the value is
// not an unsigned integer.
func ProtectedHeaderTreeSize(protectedHeader []byte) (uint64, error) {
	m, err := decodeProtectedHeader(protectedHeader)
	if err != nil {
		return 0, err
	}
	v, ok := m[CheckpointLabelTreeSize2]
	if !ok {
		return 0, fmt.Errorf("%w: label %d", ErrSignedSizeMissing, CheckpointLabelTreeSize2)
	}
	size, ok := v.(uint64)
	if !ok {
		return 0, fmt.Errorf("%w: tree-size-2 is not an unsigned integer", ErrProtectedHeaderInvalid)
	}
	return size, nil
}
