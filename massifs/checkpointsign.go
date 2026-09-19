package massifs

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
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

// SignCheckpointReceipt produces a format-v3 checkpoint object (draft-bryce
// COSE Receipt of Consistency, ADR-0046): it signs the detached raw-concat
// payload of the accumulator for the seal's mmr size, over the COSE
// Sig_structure the univocity contract verifies, and encodes the receipt with
// the consistency proof in the unprotected header.
//
// The signer is the log's COSE signer (the sealer's delegated ES256/KMS key,
// or a root key). The protected header is
// {1: alg, 395: vds=3, -65932: tree-size-1, -65933: tree-size-2}: the
// contract reads the algorithm from label 1 and derives the same detached
// payload from the proof, so the signature verifies on-chain, and both
// tree sizes are signed alongside it (ADR-0066 D1). This function signs a
// single consistency proof, so the signed tree-size-1 and tree-size-2 are
// exactly that proof's TreeSize1 and TreeSize2 (ADR-0066 D2 chain semantics:
// a receipt carrying several proofs would sign the first proof's
// tree-size-1 and the last proof's tree-size-2, which is not this
// function's case). The contract and every off-chain verifier compare the
// signed sizes against the declared proof sizes (ADR-0066 D5.5). The
// delegation proof and CWT claims are added by the sealer/consumer layers as
// needed.
//
// With WithPeakReceipts, one additional detached-payload COSE_Sign1 is signed
// per accumulator peak and carried in the unprotected header, enabling any
// holder of the checkpoint and replicated log data to mint inclusion receipts
// without the signing key.
func SignCheckpointReceipt(
	signer cose.Signer, proof ConsistencyProof, accumulator [][]byte,
	opts ...CheckpointSignOption,
) ([]byte, error) {
	var options checkpointSignOptions
	for _, opt := range opts {
		opt(&options)
	}

	protected, err := canonicalReceiptCBOR.Marshal(map[int64]any{
		checkpointLabelAlg:       int64(signer.Algorithm()),
		checkpointLabelVDS:       CheckpointVDSConsistency,
		CheckpointLabelTreeSize1: proof.TreeSize1,
		CheckpointLabelTreeSize2: proof.TreeSize2,
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
		return EncodeCheckpointReceipt(protected, proof, signature)
	}
	return EncodeCheckpointReceipt(protected, proof, signature, extras)
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

// protectedHeaderInt decodes a checkpoint receipt's protected header and
// reads a single label as a signed integer (used for the algorithm label,
// which the COSE algorithm registry defines as negative for the algorithms
// this package signs with).
func protectedHeaderInt(protectedHeader []byte, label int64) (int64, error) {
	var m map[int64]cbor.RawMessage
	if err := cbor.Unmarshal(protectedHeader, &m); err != nil {
		return 0, fmt.Errorf("decode protected header: %w", err)
	}
	raw, ok := m[label]
	if !ok {
		return 0, fmt.Errorf("protected header has no value for label %d", label)
	}
	var v int64
	if err := cbor.Unmarshal(raw, &v); err != nil {
		return 0, fmt.Errorf("decode protected header label %d: %w", label, err)
	}
	return v, nil
}

// protectedHeaderUint decodes a checkpoint receipt's protected header and
// reads a single label as an unsigned integer (used for the signed tree
// sizes, ADR-0066 D1, which are always non-negative).
func protectedHeaderUint(protectedHeader []byte, label int64) (uint64, error) {
	var m map[int64]cbor.RawMessage
	if err := cbor.Unmarshal(protectedHeader, &m); err != nil {
		return 0, fmt.Errorf("decode protected header: %w", err)
	}
	raw, ok := m[label]
	if !ok {
		return 0, fmt.Errorf("protected header has no value for label %d", label)
	}
	var v uint64
	if err := cbor.Unmarshal(raw, &v); err != nil {
		return 0, fmt.Errorf("decode protected header label %d as uint: %w", label, err)
	}
	return v, nil
}

// ProtectedHeaderAlgorithm reads the COSE algorithm from a checkpoint receipt's
// protected header (label 1), as the contract does. Useful for consumers
// selecting a verification path.
func ProtectedHeaderAlgorithm(protectedHeader []byte) (int64, error) {
	return protectedHeaderInt(protectedHeader, checkpointLabelAlg)
}

// ProtectedHeaderTreeSizes reads the signed tree-size-1 and tree-size-2 from
// a checkpoint receipt's protected header (labels CheckpointLabelTreeSize1
// and CheckpointLabelTreeSize2, ADR-0066 D1, D3). It errors if either label
// is absent or is not an unsigned integer, which is the case for any
// protected header signed before ADR-0066 (the {1, 395} form carries neither
// label).
func ProtectedHeaderTreeSizes(protectedHeader []byte) (treeSize1, treeSize2 uint64, err error) {
	treeSize1, err = protectedHeaderUint(protectedHeader, CheckpointLabelTreeSize1)
	if err != nil {
		return 0, 0, fmt.Errorf("tree-size-1: %w", err)
	}
	treeSize2, err = protectedHeaderUint(protectedHeader, CheckpointLabelTreeSize2)
	if err != nil {
		return 0, 0, fmt.Errorf("tree-size-2: %w", err)
	}
	return treeSize1, treeSize2, nil
}
