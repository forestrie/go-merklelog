package massifs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	commoncbor "github.com/forestrie/go-merklelog/massifs/cbor"
	commoncose "github.com/forestrie/go-merklelog/massifs/cose"
	"github.com/forestrie/go-merklelog/mmr"
	"github.com/veraison/go-cose"
)

// MMRIVER COSE Receipts to accompany our COSE MMRIVER seals

type MMRiverInclusionProof struct {
	Index         uint64   `cbor:"1,keyasint"`
	InclusionPath [][]byte `cbor:"2,keyasint"`
}

type MMRiverConsistencyProof struct {
	TreeSize1        uint64   `cbor:"1,keyasint"`
	TreeSize2        uint64   `cbor:"2,keyasint"`
	ConsistencyPaths [][]byte `cbor:"3,keyasint"`
	RightPeaks       [][]byte `cbor:"4,keyasint"`
}

type MMRiverVerifiableProofs struct {
	InclusionProofs   []MMRiverInclusionProof   `cbor:"-1,keyasint,omitempty"`
	ConsistencyProofs []MMRiverConsistencyProof `cbor:"-2,keyasint,omitempty"`
}

// MMRiverVerifiableProofsHeader provides for encoding, and defered decoding, of
// COSE_Sign1 message headers for MMRIVER receipts
type MMRiverVerifiableProofsHeader struct {
	VerifiableProofs MMRiverVerifiableProofs `cbor:"396,keyasint"`
}

// VerifySignedInclusionReceipts verifies a signed COSE receipt encoded according to the MMRIVER VDS
// on success the produced root is returned.
// Signature verification failure is not an error, but the returned root will be nil and the result will be false.
// All other unexpected issues are returned as errors, with a false result and nil root.
// Note that MMRIVER receipts allow for multiple inclusion proofs to be attached to the receipt.
// This function returns true only if ALL receipts verify
//
// The verifier is required: peak receipt signatures carry no key material,
// the log's public key is obtained from a trusted store, exactly as for
// checkpoint verification.
//
// The candidates array provides the *candidate* values. Once verified, we can call them node values (or leaves),
// Note that any node value in the log may be proven by a receipt, not just leaves.
func VerifySignedInclusionReceipts(
	ctx context.Context,
	receipt *commoncose.CoseSign1Message,
	verifier cose.Verifier,
	candidates [][]byte,
) (bool, []byte, error) {
	var err error

	if verifier == nil {
		return false, nil, ErrVerifierRequired
	}

	// ignore any existing payload
	receipt.Payload = nil

	// We must return false if there are no candidates
	if len(candidates) == 0 {
		return false, nil, fmt.Errorf("no candidates provided")
	}

	var header MMRiverVerifiableProofsHeader
	err = cbor.Unmarshal(receipt.Headers.RawUnprotected, &header)
	if err != nil {
		return false, nil, fmt.Errorf("MMRIVER receipt proofs malformed")
	}
	verifiableProofs := header.VerifiableProofs
	if len(verifiableProofs.InclusionProofs) == 0 {
		return false, nil, fmt.Errorf("MMRIVER receipt inclusion proofs not present")
	}

	// permit *fewer* candidates than proofs, but not more
	if len(candidates) > len(verifiableProofs.InclusionProofs) {
		return false, nil, fmt.Errorf("MMRIVER receipt more candidates than proofs")
	}

	var proof MMRiverInclusionProof

	proof = verifiableProofs.InclusionProofs[0]
	receipt.Payload = mmr.IncludedRoot(
		sha256.New(),
		proof.Index, candidates[0],
		proof.InclusionPath)

	err = receipt.Verify(nil, verifier)
	if err != nil {
		return false, nil, fmt.Errorf(
			"MMRIVER receipt VERIFY FAILED for: mmrIndex %d, candidate %d, err %v", proof.Index, 0, err)
	}
	// verify the first proof then just compare the produced roots

	for i := 1; i < len(verifiableProofs.InclusionProofs); i++ {

		proof = verifiableProofs.InclusionProofs[i]
		proven := mmr.IncludedRoot(sha256.New(), proof.Index, candidates[i], proof.InclusionPath)
		if !bytes.Equal(receipt.Payload, proven) {
			return false, nil, fmt.Errorf(
				"MMRIVER receipt VERIFY FAILED for: mmrIndex %d, candidate %d, err %v", proof.Index, i, err)
		}
	}
	return true, receipt.Payload, nil
}

// VerifySignedInclusionReceipt verifies a reciept comprised of a single inclusion proof
// If there are 0 or more than 1 candidates, the result will be false and an error will be returned
func VerifySignedInclusionReceipt(
	ctx context.Context,
	receipt *commoncose.CoseSign1Message,
	verifier cose.Verifier,
	candidate []byte,
) (bool, []byte, error) {
	ok, root, err := VerifySignedInclusionReceipts(ctx, receipt, verifier, [][]byte{candidate})
	if err != nil {
		return false, nil, err
	}
	if !ok {
		return false, nil, nil
	}
	return true, root, nil
}

// NewReceipt mints a COSE Receipt of inclusion for mmrIndex from replicated
// log data alone: the checkpoint's pre-signed peak receipt for the peak
// committing mmrIndex, with the inclusion proof attached to its unprotected
// header. No signing key is involved - any party holding the checkpoint and
// massif data can produce receipts, in a privacy preserving way: the entry of
// interest is never revealed to the log service.
//
// The verifier is used to verify the massif context against its checkpoint
// before the proof is generated; the minted receipt is verified by relying
// parties with VerifySignedInclusionReceipt and the log public key.
func NewReceipt(
	ctx context.Context,
	reader ObjectReader,
	verifier cose.Verifier,
	massifHeight uint8,
	mmrIndex uint64,
) (*commoncose.CoseSign1Message, error) {
	massifIndex := uint32(MassifIndexFromMMRIndex(massifHeight, mmrIndex))

	verified, err := GetContextVerified(ctx, reader, verifier, massifIndex)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: failed to get verified context %d", err, massifIndex)
	}
	check := verified.Checkpoint

	if mmrIndex >= check.MMRSize {
		return nil, fmt.Errorf(
			"mmr index %d is not covered by the checkpoint for massif %d (sealed size %d)",
			mmrIndex, massifIndex, check.MMRSize)
	}
	if len(check.Receipt.PeakReceipts) == 0 {
		return nil, fmt.Errorf(
			"checkpoint for massif %d carries no pre-signed peak receipts (label %d)",
			massifIndex, SealPeakReceiptsLabel)
	}

	proof, err := mmr.InclusionProof(&verified.MassifContext, check.MMRSize-1, mmrIndex)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to generate inclusion proof: %d in MMR(%d), %v",
			mmrIndex, check.MMRSize, err)
	}

	// NOTE: The old-accumulator compatibility property, from
	// https://eprint.iacr.org/2015/718.pdf, along with the COSE protected &
	// unprotected buckets, is why we can just pre sign the receipts.
	// As long as the receipt consumer is convinced of the logs consistency (not split view),
	// it does not matter which accumulator state the receipt is signed against.
	//
	// The peak committing any node (leaf or interior) is the first peak whose
	// position is >= the node's position: peaks ascend in position and each
	// covers the range between its predecessor and itself.
	peakIndex := -1
	for i, position := range mmr.Peaks(check.MMRSize - 1) {
		if mmrIndex <= position {
			peakIndex = i
			break
		}
	}
	if peakIndex < 0 || peakIndex >= len(check.Receipt.PeakReceipts) {
		return nil, fmt.Errorf(
			"checkpoint for massif %d has no peak receipt committing mmr index %d",
			massifIndex, mmrIndex)
	}

	signed, err := commoncose.NewCoseSign1MessageFromCBOR(
		check.Receipt.PeakReceipts[peakIndex],
		commoncose.WithDecOptions(commoncbor.DecOptions))
	if err != nil {
		return nil, fmt.Errorf(
			"%w: failed to decode pre-signed peak receipt for: %d in MMR(%d)",
			err, mmrIndex, check.MMRSize)
	}

	signed.Headers.RawUnprotected = nil
	if signed.Headers.Unprotected == nil {
		signed.Headers.Unprotected = cose.UnprotectedHeader{}
	}
	signed.Headers.Unprotected[checkpointLabelVDP] = MMRiverVerifiableProofs{
		InclusionProofs: []MMRiverInclusionProof{{
			Index:         mmrIndex,
			InclusionPath: proof,
		}},
	}

	return signed, nil
}
