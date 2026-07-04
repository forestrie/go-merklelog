package massifs

import (
	"errors"
)

var ErrLogContextNotRead = errors.New("attempted to use lastContext before it was read")

// Checkpoint is a checkpoint object read from a store: the raw format-v3
// receipt bytes as stored, the decoded receipt, and the sealed mmr size it
// commits to. The accumulator is not carried here; it is recovered from the
// massif data during verification (see VerifyCheckpointReceipt).
type Checkpoint struct {
	// Raw is the stored checkpoint object verbatim. Replication copies these
	// bytes rather than re-encoding the decoded parts, so unprotected header
	// content the decoder does not model (delegation material, certificates)
	// survives the copy.
	Raw []byte
	// Receipt is the decoded format-v3 consistency receipt.
	Receipt CheckpointReceipt
	// MMRSize is the sealed mmr size committed by the receipt (the proof's
	// tree-size-2).
	MMRSize uint64
}

// NewCheckpoint decodes stored checkpoint object bytes into a Checkpoint.
func NewCheckpoint(data []byte) (Checkpoint, error) {
	receipt, err := DecodeCheckpointReceipt(data)
	if err != nil {
		return Checkpoint{}, err
	}
	return Checkpoint{
		Raw:     data,
		Receipt: receipt,
		MMRSize: receipt.Proof.TreeSize2,
	}, nil
}
