package massifs

import (
	commoncbor "github.com/datatrails/go-datatrails-merklelog/massifs/cbor"
	"github.com/datatrails/go-datatrails-merklelog/massifs/storage"
	"github.com/veraison/go-cose"
)

type StorageOptions struct {
	LogID           storage.LogID
	CommitmentEpoch uint8
	MassifHeight    uint8
	CBORCodec       *commoncbor.CBORCodec
	COSEVerifier    cose.Verifier
}
type VerifyOptions struct {
	Check            *Checkpoint
	TrustedBaseState *MMRState
	CBORCodec        *commoncbor.CBORCodec
	COSEVerifier     cose.Verifier
}

// Option is a generic option type used for storage implementations.
// Implementations type assert to Options target record and if that fails the
// expectation they ignore the options
type Option func(any)

func WithCBORCodec(codec *commoncbor.CBORCodec) func(any) {
	return func(opts any) {
		if storageOpts, ok := opts.(*StorageOptions); ok {
			storageOpts.CBORCodec = codec
		}
	}
}

func WithCOSEVerifier(verifier cose.Verifier) func(any) {
	return func(opts any) {
		if storageOpts, ok := opts.(*StorageOptions); ok {
			storageOpts.COSEVerifier = verifier
		}
	}
}

func WithVerifyCheckpoint(check *Checkpoint) Option {
	return func(a any) {
		opts, ok := a.(*VerifyOptions)
		if !ok {
			return
		}
		opts.Check = check
	}
}

func WithVerifyTrustedState(state MMRState) Option {
	return func(a any) {
		opts, ok := a.(*VerifyOptions)
		if !ok {
			return
		}
		opts.TrustedBaseState = &state
	}
}
func VerifyWithCBORCodec(codec *commoncbor.CBORCodec) func(any) {
	return func(opts any) {
		if verifyOpts, ok := opts.(*VerifyOptions); ok {
			verifyOpts.CBORCodec = codec
		}
	}
}

func VerifyWithCOSEVerifier(verifier cose.Verifier) func(any) {
	return func(opts any) {
		if verifyOpts, ok := opts.(*VerifyOptions); ok {
			verifyOpts.COSEVerifier = verifier
		}
	}
}
