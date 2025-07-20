package storage

import (
	"github.com/veraison/go-cose"
	commoncbor "github.com/datatrails/go-datatrails-common/cbor"
)

type Options struct {
	LogID           LogID
	CommitmentEpoch uint8
	MassifHeight    uint8
	CBORCodec       *commoncbor.CBORCodec
	COSEVerifier    cose.Verifier
	PathProvider    PathProvider
}

// Option is a generic option type used for storage implementations.
// Implementations type assert to Options target record and if that fails the
// expectation they ignore the options
type Option func(any)
