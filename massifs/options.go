package massifs

import (
	commoncbor "github.com/datatrails/go-datatrails-common/cbor"
	"github.com/datatrails/go-datatrails-merklelog/massifs/storage"
	"github.com/veraison/go-cose"
)

type StorageOptions struct {
	LogID           storage.LogID
	CommitmentEpoch uint8
	MassifHeight    uint8
	CBORCodec       *commoncbor.CBORCodec
	COSEVerifier    cose.Verifier
	PathProvider    storage.PathProvider
}

// Option is a generic option type used for storage implementations.
// Implementations type assert to Options target record and if that fails the
// expectation they ignore the options
type Option func(any)
