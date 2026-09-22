package massifs

import (
	"bytes"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// Checkpoint format v3 (ADR-0046, sizes: ADR-0066): the sealed checkpoint
// object is a draft-bryce COSE Receipt of Consistency. It is a COSE Sign1
// with a detached payload (the raw concatenation of the accumulator peaks,
// see DetachedPayload), carrying one or more consistency proofs and a
// protected header that signs the last proof's tree-size-2 (ADR-0066 D1,
// D2). One sealed step contributes one proof; a receipt that relays a
// catch-up over several sealed steps carries them in order, each starting at
// the previous one's tree-size-2, and the signature covers the accumulator
// the last one reaches. A publisher decodes it into the pre-decoded parts the
// univocity publishCheckpoint contract takes; the contract's
// ConsistencyProof[] calldata is that same chain.
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
	// checkpointKeyConsistencyProof is the verifiable-proofs map key under
	// which a checkpoint receipt carries its consistency proofs (draft:
	// consistency-proof). The value is `consistency-proofs = [ +
	// consistency-proof ]`, an array of one or more encoded proofs.
	checkpointKeyConsistencyProof int64 = -2

	// COSEPrivateStart is the arithmetic base Forestrie's derived private-use
	// labels are allocated from (SealPeakReceiptsLabel and
	// SealDelegationProofLabel below subtract a registered label from it). It
	// is NOT the IANA boundary: IANA reserves labels less than -65536 for
	// private use, and -65535 and -65536 themselves are Specification
	// Required. Allocation in the private-use range MUST be coordinated
	// Forestrie wide; see forestrie/protocol spec/label-registry.md.
	COSEPrivateStart int64 = -65535

	// CheckpointLabelTreeSize2 is the protected header label carrying the
	// signed tree-size-2 of the consistency proof: the size at which the
	// signed accumulator was read (ADR-0066; protocol spec/label-registry.md).
	// It is an interim private-use value following the registry's derived
	// convention (COSEPrivateStart - <related label>), treating 398 as the
	// conceptual protected-header slot after vds (395), vdp (396) and 397.
	// It is a uint and MUST be present on a receipt of consistency under this
	// profile. tree-size-1 is not signed: it travels in the unprotected
	// consistency-proof structure as prover context, and every verifier takes
	// the origin size from state it already trusts (ADR-0066 D5).
	CheckpointLabelTreeSize2 int64 = COSEPrivateStart - 398

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

	// SealDelegationProofLabel is the private-use unprotected header label
	// under which a checkpoint carries the univocity on-chain delegation
	// proof: the root key's signature binding the delegated checkpoint
	// signing key to (logId, mmrStart, mmrEnd). The publisher wires it into
	// the publishCheckpoint calldata delegationProof. The value is opaque to
	// this package (an arbor-defined CBOR wire object, plan-0003
	// OnchainDelegationProof); it is exposed via CheckpointReceipt.Extras.
	// The 1000 offset mirrors the legacy delegation certificate label.
	SealDelegationProofLabel int64 = COSEPrivateStart - 1000
)

// coseSign1Tag is the CBOR initial byte for tag 18 (COSE_Sign1). Tag values
// 0..23 encode in the tag's single initial byte: 0xc0 | 18 = 0xd2.
const coseSign1Tag byte = 0xd2

// cborMajorByteString is CBOR major type 2, which distinguishes a bare
// consistency-proof from the consistency-proofs array (major type 4).
const cborMajorByteString byte = 2

// cborMajorArray is CBOR major type 4, the consistency-proofs array form.
const cborMajorArray byte = 4

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
// COSE Sign1 parts plus the consistency proofs it carries. The detached
// payload is not stored in the object; a verifier reconstructs it by folding
// the proofs from a state it already trusts (see
// VerifyCheckpointReceiptFromState) and DetachedPayload.
type CheckpointReceipt struct {
	ProtectedHeader []byte
	Signature       []byte
	// Proofs is the chain the receipt carries, in order: the first proof
	// starts at the size the verifier already trusts, each later proof starts
	// at its predecessor's tree-size-2, and the last proof's tree-size-2 is
	// the size the protected header signs. A receipt carrying no proof does
	// not decode (ErrProofChainEmpty).
	Proofs []ConsistencyProof
	// Proof is a copy of the last element of Proofs, set by
	// DecodeCheckpointReceipt so that callers written against the
	// single-proof receipt keep compiling. It is read-only compatibility:
	// verification reads Proofs, so a change made here alone has no effect,
	// and on a relayed chain this field is only the final link.
	Proof ConsistencyProof
	// PeakReceipts, when present, are the pre-signed peak inclusion receipts
	// carried under SealPeakReceiptsLabel: one encoded detached-payload
	// COSE_Sign1 per accumulator peak, in accumulator (descending height)
	// order.
	PeakReceipts [][]byte
	// Extras carries the unprotected header labels this decoder does not
	// model (delegation material under SealDelegationProofLabel,
	// certificates), values verbatim. Nil when there are none. Replication
	// does not depend on this - it copies the stored object bytes - but
	// consumers such as the publisher read their labels from here.
	Extras map[int64]cbor.RawMessage
}

// canonicalReceiptCBOR encodes deterministically (RFC 8949 canonical) so
// encodings are stable across producers.
var canonicalReceiptCBOR cbor.EncMode

// receiptDecMode is the strict decode mode for every unmarshal that reads a
// checkpoint receipt (GML15-F1): duplicate map keys and indefinite-length
// items have more than one reading, so accepting either would let two
// implementations disagree on what a receipt says while both call it valid.
// TagsMd is left at its default (tags allowed): peak receipts and other
// unprotected header values are legitimately tagged COSE objects. This mode
// only narrows the wire-form envelope; it does not establish canonical key
// order or shortest-form integers, which fxamacker has no option for and are
// instead checked by re-marshalling with canonicalReceiptCBOR and comparing
// to the input bytes (see decodeConsistencyProofs, DecodeConsistencyProof and
// DecodeCheckpointReceipt).
var receiptDecMode cbor.DecMode

func init() {
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("massifs: canonical cbor mode: %v", err))
	}
	canonicalReceiptCBOR = em

	dm, err := cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
		IndefLength: cbor.IndefLengthForbidden,
	}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("massifs: strict checkpoint receipt cbor mode: %v", err))
	}
	receiptDecMode = dm
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
// the CBOR array of the four fields. A nil inner path is normalised to an
// empty array before marshalling, the same as the top-level Paths/RightPeaks
// nil below (GML15-F3): mmr.IndexConsistencyProof (via BuildConsistencyProof)
// returns a nil path for every tree-size-1 accumulator peak above the split,
// and fxamacker marshals a nil [][]byte as CBOR null rather than an empty
// array. Null has no place in the draft CDDL there, and the TS twin decoder
// rejects it, so a copy is normalised here rather than mutating the caller's
// slices in place.
func EncodeConsistencyProof(p ConsistencyProof) ([]byte, error) {
	paths := make([][][]byte, len(p.Paths))
	copy(paths, p.Paths)
	for i, path := range paths {
		if path == nil {
			paths[i] = [][]byte{}
		}
	}
	rightPeaks := p.RightPeaks
	if rightPeaks == nil {
		rightPeaks = [][]byte{}
	}
	cp := cborConsistencyProof{
		TreeSize1:  p.TreeSize1,
		TreeSize2:  p.TreeSize2,
		Paths:      paths,
		RightPeaks: rightPeaks,
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

// DecodeConsistencyProof reverses EncodeConsistencyProof. The inner array
// must be canonically encoded (GML15-F1): fxamacker has no decode option for
// canonical form or shortest-form integers, so this re-marshals the decoded
// tuple with canonicalReceiptCBOR and requires the bytes to match the input,
// which also catches a non-shortest-form integer field. Paths/RightPeaks are
// normalised nil -> empty before the comparison, the same normalisation
// EncodeConsistencyProof applies before marshalling, so a canonical `80`
// empty array round-trips.
func DecodeConsistencyProof(bstr []byte) (ConsistencyProof, error) {
	var inner []byte
	if err := receiptDecMode.Unmarshal(bstr, &inner); err != nil {
		return ConsistencyProof{}, fmt.Errorf("unwrap consistency proof bstr: %w", err)
	}
	var cp cborConsistencyProof
	if err := receiptDecMode.Unmarshal(inner, &cp); err != nil {
		return ConsistencyProof{}, fmt.Errorf("decode consistency proof array: %w", err)
	}
	if cp.Paths == nil {
		cp.Paths = [][][]byte{}
	}
	if cp.RightPeaks == nil {
		cp.RightPeaks = [][]byte{}
	}
	// Only the top-level slices are normalised here: an inner path decoded
	// from CBOR null is left nil, so the re-marshal below reproduces the
	// same null and still compares equal to a proof sealed before GML15-F3,
	// which this decoder continues to accept.
	canonical, err := canonicalReceiptCBOR.Marshal(cp)
	if err != nil {
		return ConsistencyProof{}, fmt.Errorf("re-encode consistency proof array: %w", err)
	}
	if !bytes.Equal(canonical, inner) {
		return ConsistencyProof{}, fmt.Errorf("decode consistency proof array: is not canonically encoded")
	}
	return ConsistencyProof{
		TreeSize1:  cp.TreeSize1,
		TreeSize2:  cp.TreeSize2,
		Paths:      cp.Paths,
		RightPeaks: cp.RightPeaks,
	}, nil
}

// EncodeCheckpointReceipt encodes a format-v3 checkpoint carrying a single
// consistency proof. See EncodeCheckpointReceiptChain, of which this is the
// one-proof case: the proof is still written as the draft's
// `consistency-proofs = [ + consistency-proof ]`, an array of one.
func EncodeCheckpointReceipt(
	protectedHeader []byte, proof ConsistencyProof, signature []byte,
	extraUnprotected ...map[int64]cbor.RawMessage,
) ([]byte, error) {
	return EncodeCheckpointReceiptChain(
		protectedHeader, []ConsistencyProof{proof}, signature, extraUnprotected...)
}

// EncodeCheckpointReceiptChain encodes a format-v3 checkpoint: a COSE Sign1
// [protected, unprotected, payload, signature] with a detached payload (null)
// and the consistency proofs under the unprotected verifiable-proofs map, as
// the draft's `consistency-proofs = [ + consistency-proof ]`. The proofs are
// in fold order: the first starts at the size a verifier already trusts and
// each later one at its predecessor's tree-size-2, the last of which is what
// protectedHeader signs. protectedHeader is the already-CBOR-encoded
// protected header bytes (carried verbatim so the on-chain signature check
// sees the signed bytes); signature is the raw COSE signature over
// SigStructure(protectedHeader, detached). extraUnprotected labels
// (pre-signed peak receipts, delegation material) are merged into the
// unprotected header; they do not affect the signature.
func EncodeCheckpointReceiptChain(
	protectedHeader []byte, proofs []ConsistencyProof, signature []byte,
	extraUnprotected ...map[int64]cbor.RawMessage,
) ([]byte, error) {
	if len(proofs) == 0 {
		return nil, ErrProofChainEmpty
	}
	encoded := make([]cbor.RawMessage, len(proofs))
	for i, proof := range proofs {
		proofBstr, err := EncodeConsistencyProof(proof)
		if err != nil {
			return nil, err
		}
		encoded[i] = proofBstr
	}
	proofArray, err := canonicalReceiptCBOR.Marshal(encoded)
	if err != nil {
		return nil, fmt.Errorf("encode consistency-proofs array: %w", err)
	}
	verifiableProofs, err := canonicalReceiptCBOR.Marshal(
		map[int64]cbor.RawMessage{checkpointKeyConsistencyProof: proofArray},
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
		if err := receiptDecMode.Unmarshal(data, &tag); err != nil {
			return CheckpointReceipt{}, fmt.Errorf("decode COSE_Sign1 tag: %w", err)
		}
		data = tag.Content
	}
	var arr []cbor.RawMessage
	if err := receiptDecMode.Unmarshal(data, &arr); err != nil {
		return CheckpointReceipt{}, fmt.Errorf("decode COSE Sign1 array: %w", err)
	}
	if len(arr) != 4 {
		return CheckpointReceipt{}, fmt.Errorf("COSE Sign1 must have 4 elements, got %d", len(arr))
	}
	var protected []byte
	if err := receiptDecMode.Unmarshal(arr[0], &protected); err != nil {
		return CheckpointReceipt{}, fmt.Errorf("decode protected header: %w", err)
	}
	var unprotected map[int64]cbor.RawMessage
	if err := receiptDecMode.Unmarshal(arr[1], &unprotected); err != nil {
		return CheckpointReceipt{}, fmt.Errorf("decode unprotected header: %w", err)
	}
	if canonical, err := canonicalReceiptCBOR.Marshal(unprotected); err != nil {
		return CheckpointReceipt{}, fmt.Errorf("re-encode unprotected header: %w", err)
	} else if !bytes.Equal(canonical, arr[1]) {
		return CheckpointReceipt{}, fmt.Errorf("decode unprotected header: is not canonically encoded")
	}
	var signature []byte
	if err := receiptDecMode.Unmarshal(arr[3], &signature); err != nil {
		return CheckpointReceipt{}, fmt.Errorf("decode signature: %w", err)
	}

	vpRaw, ok := unprotected[checkpointLabelVDP]
	if !ok {
		return CheckpointReceipt{}, fmt.Errorf("receipt has no verifiable-proofs (label %d)", checkpointLabelVDP)
	}
	var vp map[int64]cbor.RawMessage
	if err := receiptDecMode.Unmarshal(vpRaw, &vp); err != nil {
		return CheckpointReceipt{}, fmt.Errorf("decode verifiable-proofs: %w", err)
	}
	if canonical, err := canonicalReceiptCBOR.Marshal(vp); err != nil {
		return CheckpointReceipt{}, fmt.Errorf("re-encode verifiable-proofs: %w", err)
	} else if !bytes.Equal(canonical, vpRaw) {
		return CheckpointReceipt{}, fmt.Errorf("decode verifiable-proofs: is not canonically encoded")
	}
	proofsRaw, ok := vp[checkpointKeyConsistencyProof]
	if !ok {
		return CheckpointReceipt{}, fmt.Errorf("verifiable-proofs has no consistency proof (key %d)", checkpointKeyConsistencyProof)
	}
	proofs, err := decodeConsistencyProofs(proofsRaw)
	if err != nil {
		return CheckpointReceipt{}, err
	}

	var peakReceipts [][]byte
	if raw, ok := unprotected[SealPeakReceiptsLabel]; ok {
		if err := receiptDecMode.Unmarshal(raw, &peakReceipts); err != nil {
			return CheckpointReceipt{}, fmt.Errorf("decode peak receipts: %w", err)
		}
	}

	var extras map[int64]cbor.RawMessage
	for label, value := range unprotected {
		if label == checkpointLabelVDP || label == SealPeakReceiptsLabel {
			continue
		}
		if extras == nil {
			extras = map[int64]cbor.RawMessage{}
		}
		extras[label] = value
	}

	return CheckpointReceipt{
		ProtectedHeader: protected,
		Signature:       signature,
		Proofs:          proofs,
		Proof:           proofs[len(proofs)-1],
		PeakReceipts:    peakReceipts,
		Extras:          extras,
	}, nil
}

// cborMajorType reads the major type of the first CBOR item in data.
func cborMajorType(data []byte) (byte, bool) {
	if len(data) == 0 {
		return 0, false
	}
	return data[0] >> 5, true
}

// decodeConsistencyProofs decodes the value under the verifiable-proofs
// consistency-proof key. The draft form is `consistency-proofs = [ +
// consistency-proof ]`, an array of one or more encoded proofs, and an empty
// array is rejected: a receipt proves something or it is not a receipt of
// consistency. A bare consistency-proof byte string is also accepted, as the
// single-proof form receipts sealed before the array form carry; it decodes
// to a chain of one. Any other major type - including a CBOR tag (major 6)
// wrapping either form - is rejected (GML15-F1): a generic COSE/CBOR reader
// that unwraps tags before this check would see a different value than one
// that does not. The array itself, and each of its elements, must be
// canonically encoded and each element must be a byte string; an array
// element of any other major type (for example a CBOR array of small
// unsigned integers, which fxamacker will happily decode into a []byte) is
// rejected before it is handed to DecodeConsistencyProof.
func decodeConsistencyProofs(raw cbor.RawMessage) ([]ConsistencyProof, error) {
	major, ok := cborMajorType(raw)
	if !ok {
		return nil, fmt.Errorf("decode consistency-proofs: empty value")
	}
	switch major {
	case cborMajorByteString:
		proof, err := DecodeConsistencyProof(raw)
		if err != nil {
			return nil, err
		}
		return []ConsistencyProof{proof}, nil
	case cborMajorArray:
		// handled below
	default:
		return nil, fmt.Errorf(
			"decode consistency-proofs: unexpected major type %d, want a byte string (2) or an array (4)", major)
	}
	var encoded []cbor.RawMessage
	if err := receiptDecMode.Unmarshal(raw, &encoded); err != nil {
		return nil, fmt.Errorf("decode consistency-proofs array: %w", err)
	}
	if len(encoded) == 0 {
		return nil, ErrProofChainEmpty
	}
	canonical, err := canonicalReceiptCBOR.Marshal(encoded)
	if err != nil {
		return nil, fmt.Errorf("re-encode consistency-proofs array: %w", err)
	}
	if !bytes.Equal(canonical, raw) {
		return nil, fmt.Errorf("decode consistency-proofs array: is not canonically encoded")
	}
	proofs := make([]ConsistencyProof, len(encoded))
	for i, item := range encoded {
		if m, ok := cborMajorType(item); !ok || m != cborMajorByteString {
			return nil, fmt.Errorf("consistency proof %d: expected a byte string", i)
		}
		proof, err := DecodeConsistencyProof(item)
		if err != nil {
			return nil, fmt.Errorf("consistency proof %d: %w", i, err)
		}
		proofs[i] = proof
	}
	return proofs, nil
}
