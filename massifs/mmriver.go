package massifs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	commoncose "github.com/forestrie/go-merklelog/massifs/cose"
	"github.com/forestrie/go-merklelog/mmr"
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
// The candidates array provides the *candidate* values. Once verified, we can call them node values (or leaves),
// Note that any node value in the log may be proven by a receipt, not just leaves.
func VerifySignedInclusionReceipts(
	ctx context.Context,
	receipt *commoncose.CoseSign1Message,
	candidates [][]byte,
) (bool, []byte, error) {
	var err error

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

	err = receipt.VerifyWithCWTPublicKey(nil)
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
	candidate []byte,
) (bool, []byte, error) {
	ok, root, err := VerifySignedInclusionReceipts(ctx, receipt, [][]byte{candidate})
	if err != nil {
		return false, nil, err
	}
	if !ok {
		return false, nil, nil
	}
	return true, root, nil
}
