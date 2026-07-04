package massifs

import (
	"crypto/rand"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// SignCheckpointReceipt produces a format-v3 checkpoint object (draft-bryce
// COSE Receipt of Consistency, ADR-0046): it signs the detached raw-concat
// payload of the accumulator for the seal's mmr size, over the COSE
// Sig_structure the univocity contract verifies, and encodes the receipt with
// the consistency proof in the unprotected header.
//
// The signer is the log's COSE signer (the sealer's delegated ES256/KMS key,
// or a root key). The protected header is {1: alg, 395: vds=3}; the contract
// reads the algorithm from label 1 and derives the same detached payload from
// the proof, so the signature verifies on-chain. The delegation proof and CWT
// claims are added by the sealer/consumer layers as needed.
func SignCheckpointReceipt(
	signer cose.Signer, proof ConsistencyProof, accumulator [][]byte,
) ([]byte, error) {
	protected, err := canonicalReceiptCBOR.Marshal(map[int64]int64{
		checkpointLabelAlg: int64(signer.Algorithm()),
		checkpointLabelVDS: CheckpointVDSConsistency,
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

	return EncodeCheckpointReceipt(protected, proof, signature)
}

// ProtectedHeaderAlgorithm reads the COSE algorithm from a checkpoint receipt's
// protected header (label 1), as the contract does. Useful for consumers
// selecting a verification path.
func ProtectedHeaderAlgorithm(protectedHeader []byte) (int64, error) {
	var m map[int64]cbor.RawMessage
	if err := cbor.Unmarshal(protectedHeader, &m); err != nil {
		return 0, fmt.Errorf("decode protected header: %w", err)
	}
	raw, ok := m[checkpointLabelAlg]
	if !ok {
		return 0, fmt.Errorf("protected header has no algorithm (label %d)", checkpointLabelAlg)
	}
	var alg int64
	if err := cbor.Unmarshal(raw, &alg); err != nil {
		return 0, fmt.Errorf("decode algorithm: %w", err)
	}
	return alg, nil
}
