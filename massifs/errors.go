package massifs

import "errors"

var ErrNotleaf = errors.New("mmr node not a leaf")

var (
	ErrGetIndexUnavailable      = errors.New("requested mmr index not available")
	ErrBeforeFirstLeaf          = errors.New("the requested leaf index is below the first leaf indexed in the blob")
	ErrMassifDataLengthInvalid  = errors.New("the length of data is incorrect given the provided mmr parameters")
	ErrLeafRange                = errors.New("the requested leaf is not in the blob (and is *after* the first leaf indexed)")
	ErrMassifFull               = errors.New("the current massif is full")
	ErrAncestorStackUnderfilled = errors.New("the ancestor stack data is to short to be valid")
	ErrAncestorStackInvalid     = errors.New("the ancestor stack is invalid due to bad header information")
	ErrIndexNotInMassif         = errors.New("mmr index not in the massif")
	ErrStateRootMissing         = errors.New("the root field of a state struct was nil when it should have been provided")
)

var (
	ErrStateSizeBeforeMassifStart = errors.New("the massif index in the mmr state must at least cover the start of the massif")
	ErrStateSizeExceedsData       = errors.New("there is insufficient data in the massif context to generate a consistency proof against the provided state")
	ErrSealGetterNotProvided      = errors.New("a seal getter was required but not provided")
	ErrCBORCodecNotProvided       = errors.New("a CBOR codec was required but not provided")
	ErrSealNotFound               = errors.New("seal not found")
	ErrSealVerifyFailed           = errors.New("the seal signature verification failed")
	ErrGeneratingConsistencyProof = errors.New("error while  creating a consistency proof")
	ErrConsistencyProofCheck      = errors.New("verification error while checking a consistency proof")
	ErrInconsistentState          = errors.New("verification failed for a consistency proof")
	ErrRemoteSealKeyMatchFailed   = errors.New("the provided public key did not match the remote sealing key")
)
