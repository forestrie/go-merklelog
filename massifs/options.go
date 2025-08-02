package massifs

import (
	commoncbor "github.com/datatrails/go-datatrails-common/cbor"
	"github.com/datatrails/go-datatrails-merklelog/massifs/storage"
	"github.com/datatrails/go-datatrails-merklelog/massifs/storageschema"
	"github.com/veraison/go-cose"
)

type StorageOptions struct {
	LogID           storage.LogID
	CommitmentEpoch uint8
	MassifHeight    uint8
	CBORCodec       *commoncbor.CBORCodec
	COSEVerifier    cose.Verifier
	PathProvider    storage.PathProvider
	PrefixProvider  storageschema.PrefixProvider
}

// Option is a generic option type used for storage implementations.
// Implementations type assert to Options target record and if that fails the
// expectation they ignore the options
type Option func(any)

func WithPathProvider(provider storage.PathProvider) Option {
	return func(opts any) {
		if o, ok := opts.(*StorageOptions); ok {
			o.PathProvider = provider
		}
	}
}

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
