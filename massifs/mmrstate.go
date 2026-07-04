package massifs

// MMRState describes an mmr state as a (size, accumulator) pair.
//
// The size of the mmr defines the path to the peaks (and the full structure
// of the tree). All subsequent mmr states whose size is *greater* can
// (efficiently) reproduce the peaks for this state, due to the strict append
// only structure of the tree.
//
// Since the format-v3 checkpoint cutover (ADR-0046) this is an in-memory
// descriptor only - used for trusted base states and consistency checks.
// Nothing decodes a checkpoint into it; checkpoints are format-v3 consistency
// receipts (see CheckpointReceipt).
type MMRState struct {
	MMRSize uint64
	// Peaks are the peak hashes for the mmr identified by MMRSize; this is
	// also the packed accumulator for the tree state. All inclusion proofs
	// for any node under MMRSize lead directly to one of these peaks, or can
	// be extended to do so.
	Peaks [][]byte
}
