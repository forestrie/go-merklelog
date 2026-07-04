package massifs

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// Checkpoint format v3 (ADR-0046): the sealed checkpoint object is a
// draft-bryce COSE Receipt of Consistency. It is a COSE Sign1 with a detached
// payload (the raw concatenation of the accumulator peaks, see
// DetachedPayload), carrying one consistency proof from the previous
// checkpoint to this seal. A publisher decodes it into the pre-decoded parts
// the univocity publishCheckpoint contract takes, and chains the proofs from
// consecutive checkpoints into the ConsistencyProof[] calldata when catching
// up over multiple seals (one seal -> one proof; the chain is assembled at
// publish time).
//
// This is the single source of the format for both the producer (the sealer,
// via rootsigner) and the consumers (verify/replicate); higher layers
// (arbor publishproof) convert these types to the on-chain calldata ABI.
//
// draft-bryce COSE Receipts MMR profile labels:
const (
	// CheckpointVDSConsistency is the verifiable-data-structure algorithm
	// identifier for the MMR consistency profile (protected header label 395).
	CheckpointVDSConsistency int64 = 3
	// checkpointLabelAlg is the COSE protected-header algorithm label.
	checkpointLabelAlg int64 = 1
	// checkpointLabelVDS is the protected-header verifiable-data-structure
	// label (draft: vds).
	checkpointLabelVDS int64 = 395
	// checkpointLabelVDP is the unprotected-header label carrying the
	// verifiable-proofs map (draft: vdp).
	checkpointLabelVDP int64 = 396
	// checkpointKeyConsistencyProof is the verifiable-proofs map key for the
	// single consistency proof a checkpoint receipt carries (draft:
	// consistency-proof).
	checkpointKeyConsistencyProof int64 = -2

	// COSEPrivateStart is the start of the COSE private-use label space
	// (numbers < -65535 are reserved for private use). Allocation in this
	// range MUST be coordinated Forestrie wide.
	COSEPrivateStart int64 = -65535

	// SealPeakReceiptsLabel is the private-use unprotected header label under
	// which a checkpoint carries pre-signed peak inclusion receipts: one
	// detached-payload COSE_Sign1 per accumulator peak, signed by the log
	// signer at seal time (payload = the peak, per the draft-bryce Receipt of
	// Inclusion). Any holder of the checkpoint and replicated massif data can
	// mint a standards-compliant, privacy-preserving inclusion receipt from
	// these without the signing key (see NewReceipt). The label is allocated
	// by subtracting the IANA registered verifiable-proofs label from the
	// private-use start.
	SealPeakReceiptsLabel int64 = COSEPrivateStart - checkpointLabelVDP
)

// coseSign1Tag is the CBOR initial byte for tag 18 (COSE_Sign1). Tag values
// 0..23 encode in the tag's single initial byte: 0xc0 | 18 = 0xd2.
const coseSign1Tag byte = 0xd2

// ConsistencyProof is the draft-bryce consistency proof (checkpoint format v3):
// the accumulator for tree-size-1 is a prefix of the accumulator for
// tree-size-2. Nodes are the raw hash bytes used throughout go-merklelog.
type ConsistencyProof struct {
	// TreeSize1 is the previous (complete) MMR size.
	TreeSize1 uint64
	// TreeSize2 is the latest (complete) MMR size.
	TreeSize2 uint64
	// Paths is the inclusion path from each accumulator peak in tree-size-1 to
	// its new peak in tree-size-2 (one path per tree-size-1 peak).
	Paths [][][]byte
	// RightPeaks are the additional peaks completing the tree-size-2
	// accumulator when appended to those produced by the paths.
	RightPeaks [][]byte
}

// CheckpointReceipt is a decoded format-v3 checkpoint object: the pre-decoded
// COSE Sign1 parts plus the single consistency proof it carries. The detached
// payload is not stored in the object; a verifier reconstructs it from the
// proof (see mmr.ConsistentRoots) and DetachedPayload.
type CheckpointReceipt struct {
	ProtectedHeader []byte
	Signature       []byte
	Proof           ConsistencyProof
	// PeakReceipts, when present, are the pre-signed peak inclusion receipts
	// carried under SealPeakReceiptsLabel: one encoded detached-payload
	// COSE_Sign1 per accumulator peak, in accumulator (descending height)
	// order.
	PeakReceipts [][]byte
}

// canonicalReceiptCBOR encodes deterministically (RFC 8949 canonical) so
// encodings are stable across producers.
var canonicalReceiptCBOR cbor.EncMode

func init() {
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("massifs: canonical cbor mode: %v", err))
	}
	canonicalReceiptCBOR = em
}

// DetachedPayload returns the COSE detached payload a consistency receipt
// signature is over (ADR-0046 / draft-bryce): the raw concatenation of the
// accumulator peaks, in descending height order, no hashing. This matches the
// univocity contract's buildDetachedPayloadCommitment, so a signer and the
// contract sign and verify over the same bytes.
func DetachedPayload(accumulator [][]byte) []byte {
	var n int
	for _, peak := range accumulator {
		n += len(peak)
	}
	out := make([]byte, 0, n)
	for _, peak := range accumulator {
		out = append(out, peak...)
	}
	return out
}

// SigStructure returns the COSE Sign1 Sig_structure the signature is computed
// over (RFC 9052): [ "Signature1", protected, external_aad = h”, payload ].
// Matches univocity cosecbor.buildSigStructure so a receipt signed here
// verifies on-chain.
func SigStructure(protectedHeader, payload []byte) []byte {
	out := []byte{0x84}
	out = append(out, 0x6a)
	out = append(out, []byte("Signature1")...)
	out = append(out, cborByteString(protectedHeader)...)
	out = append(out, 0x40)
	out = append(out, cborByteString(payload)...)
	return out
}

// cborByteString encodes a definite-length CBOR byte string header + bytes.
func cborByteString(data []byte) []byte {
	n := len(data)
	var head []byte
	switch {
	case n < 24:
		head = []byte{0x40 + byte(n)}
	case n < 256:
		head = []byte{0x58, byte(n)}
	case n < 1<<16:
		head = []byte{0x59, byte(n >> 8), byte(n)}
	default:
		panic(fmt.Sprintf("massifs: byte string of %d bytes exceeds checkpoint material bounds", n))
	}
	return append(head, data...)
}

// cborConsistencyProof is the draft-bryce consistency proof encoded as a CBOR
// array: [tree-size-1, tree-size-2, consistency-paths, right-peaks].
type cborConsistencyProof struct {
	_          struct{} `cbor:",toarray"`
	TreeSize1  uint64
	TreeSize2  uint64
	Paths      [][][]byte
	RightPeaks [][]byte
}

// EncodeConsistencyProof encodes one consistency proof as the draft's
// `consistency-proof = bstr .cbor [...]`: a CBOR byte string whose content is
// the CBOR array of the four fields.
func EncodeConsistencyProof(p ConsistencyProof) ([]byte, error) {
	cp := cborConsistencyProof{
		TreeSize1:  p.TreeSize1,
		TreeSize2:  p.TreeSize2,
		Paths:      p.Paths,
		RightPeaks: p.RightPeaks,
	}
	if cp.Paths == nil {
		cp.Paths = [][][]byte{}
	}
	if cp.RightPeaks == nil {
		cp.RightPeaks = [][]byte{}
	}
	inner, err := canonicalReceiptCBOR.Marshal(cp)
	if err != nil {
		return nil, fmt.Errorf("encode consistency proof array: %w", err)
	}
	bstr, err := canonicalReceiptCBOR.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("wrap consistency proof bstr: %w", err)
	}
	return bstr, nil
}

// DecodeConsistencyProof reverses EncodeConsistencyProof.
func DecodeConsistencyProof(bstr []byte) (ConsistencyProof, error) {
	var inner []byte
	if err := cbor.Unmarshal(bstr, &inner); err != nil {
		return ConsistencyProof{}, fmt.Errorf("unwrap consistency proof bstr: %w", err)
	}
	var cp cborConsistencyProof
	if err := cbor.Unmarshal(inner, &cp); err != nil {
		return ConsistencyProof{}, fmt.Errorf("decode consistency proof array: %w", err)
	}
	return ConsistencyProof{
		TreeSize1:  cp.TreeSize1,
		TreeSize2:  cp.TreeSize2,
		Paths:      cp.Paths,
		RightPeaks: cp.RightPeaks,
	}, nil
}

// EncodeCheckpointReceipt encodes a format-v3 checkpoint: a COSE Sign1
// [protected, unprotected, payload, signature] with a detached payload (null)
// and the consistency proof under the unprotected verifiable-proofs map.
// protectedHeader is the already-CBOR-encoded protected header bytes (carried
// verbatim so the on-chain signature check sees the signed bytes); signature
// is the raw COSE signature over SigStructure(protectedHeader, detached).
// extraUnprotected labels (pre-signed peak receipts, delegation material) are
// merged into the unprotected header; they do not affect the signature.
func EncodeCheckpointReceipt(
	protectedHeader []byte, proof ConsistencyProof, signature []byte,
	extraUnprotected ...map[int64]cbor.RawMessage,
) ([]byte, error) {
	proofBstr, err := EncodeConsistencyProof(proof)
	if err != nil {
		return nil, err
	}
	verifiableProofs, err := canonicalReceiptCBOR.Marshal(
		map[int64]cbor.RawMessage{checkpointKeyConsistencyProof: proofBstr},
	)
	if err != nil {
		return nil, fmt.Errorf("encode verifiable-proofs: %w", err)
	}
	unprotected := map[int64]cbor.RawMessage{checkpointLabelVDP: verifiableProofs}
	for _, extras := range extraUnprotected {
		for label, value := range extras {
			if _, exists := unprotected[label]; exists {
				return nil, fmt.Errorf("duplicate unprotected header label %d", label)
			}
			unprotected[label] = value
		}
	}

	// Tagged COSE_Sign1 (CBOR tag 18): [protected: bstr, unprotected: map,
	// payload: null (detached), signature: bstr]. The tag lets generic COSE
	// tooling recognise the object. The univocity contract takes pre-decoded
	// parts and never parses this envelope, so it is unaffected.
	sign1 := []any{protectedHeader, unprotected, nil, signature}
	out, err := canonicalReceiptCBOR.Marshal(cbor.Tag{Number: 18, Content: sign1})
	if err != nil {
		return nil, fmt.Errorf("encode checkpoint receipt: %w", err)
	}
	return out, nil
}

// DecodeCheckpointReceipt decodes a format-v3 checkpoint object into its
// pre-decoded parts.
func DecodeCheckpointReceipt(data []byte) (CheckpointReceipt, error) {
	// Unwrap the COSE_Sign1 tag (18) if present.
	if len(data) > 0 && data[0] == coseSign1Tag {
		var tag cbor.RawTag
		if err := cbor.Unmarshal(data, &tag); err != nil {
			return CheckpointReceipt{}, fmt.Errorf("decode COSE_Sign1 tag: %w", err)
		}
		data = tag.Content
	}
	var arr []cbor.RawMessage
	if err := cbor.Unmarshal(data, &arr); err != nil {
		return CheckpointReceipt{}, fmt.Errorf("decode COSE Sign1 array: %w", err)
	}
	if len(arr) != 4 {
		return CheckpointReceipt{}, fmt.Errorf("COSE Sign1 must have 4 elements, got %d", len(arr))
	}
	var protected []byte
	if err := cbor.Unmarshal(arr[0], &protected); err != nil {
		return CheckpointReceipt{}, fmt.Errorf("decode protected header: %w", err)
	}
	var unprotected map[int64]cbor.RawMessage
	if err := cbor.Unmarshal(arr[1], &unprotected); err != nil {
		return CheckpointReceipt{}, fmt.Errorf("decode unprotected header: %w", err)
	}
	var signature []byte
	if err := cbor.Unmarshal(arr[3], &signature); err != nil {
		return CheckpointReceipt{}, fmt.Errorf("decode signature: %w", err)
	}

	vpRaw, ok := unprotected[checkpointLabelVDP]
	if !ok {
		return CheckpointReceipt{}, fmt.Errorf("receipt has no verifiable-proofs (label %d)", checkpointLabelVDP)
	}
	var vp map[int64]cbor.RawMessage
	if err := cbor.Unmarshal(vpRaw, &vp); err != nil {
		return CheckpointReceipt{}, fmt.Errorf("decode verifiable-proofs: %w", err)
	}
	proofBstr, ok := vp[checkpointKeyConsistencyProof]
	if !ok {
		return CheckpointReceipt{}, fmt.Errorf("verifiable-proofs has no consistency proof (key %d)", checkpointKeyConsistencyProof)
	}
	proof, err := DecodeConsistencyProof(proofBstr)
	if err != nil {
		return CheckpointReceipt{}, err
	}

	var peakReceipts [][]byte
	if raw, ok := unprotected[SealPeakReceiptsLabel]; ok {
		if err := cbor.Unmarshal(raw, &peakReceipts); err != nil {
			return CheckpointReceipt{}, fmt.Errorf("decode peak receipts: %w", err)
		}
	}

	return CheckpointReceipt{
		ProtectedHeader: protected,
		Signature:       signature,
		Proof:           proof,
		PeakReceipts:    peakReceipts,
	}, nil
}
