package cbor

import (
	"github.com/fxamacker/cbor/v2"
)

var (
	EncOptions = NewDeterministicEncOpts()
	DecOptions = cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF, // (default) duplicated key not allowed
		IndefLength: cbor.IndefLengthForbidden, // (default) no streaming
		// override the default decoding behaviour for unsigned integers to retain the sign
		IntDec: cbor.IntDecConvertNone, // decode CBOR uint/int to Go int64
		TagsMd: cbor.TagsForbidden,     // (default) no tags
	}
)

// CBORConfig provides the properties necessary to configure cbor encoding
// and decoding for scitt
type CBORConfig struct {
	EncMode              cbor.EncMode
	DecMode              cbor.DecMode
	DecModeTagsForbidden cbor.DecMode
}

func NewDeterministicEncOpts() cbor.EncOptions {
	return cbor.EncOptions{
		Sort:        cbor.SortCoreDeterministic,
		IndefLength: cbor.IndefLengthForbidden,
	}
}

// NewDeterministicDecOptsConvertSigned is used when deterministic input is
// expected and both unsigned and signed integers should be decoded to int64
func NewDeterministicDecOptsConvertSigned() cbor.DecOptions {
	return cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF, // duplicated key not allowed
		IndefLength: cbor.IndefLengthForbidden, // no streaming
		IntDec:      cbor.IntDecConvertSigned,  // decode CBOR uint/int to Go int64
		TagsMd:      cbor.TagsForbidden,
	}
}

// NewDeterministicDecOpts is used when deterministic input is expected and
// unsigned and signed integers should be decoded to uint64 and int64
// respectively.
func NewDeterministicDecOpts() cbor.DecOptions {
	return cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF, // duplicated key not allowed
		IndefLength: cbor.IndefLengthForbidden, // no streaming
		IntDec:      cbor.IntDecConvertNone,    // decode CBOR uint/int to Go int64
		TagsMd:      cbor.TagsForbidden,
	}
}

func NewCBORConfig(
	encOpts cbor.EncOptions, decOpts cbor.DecOptions,
) (CBORConfig, error) {

	var err error

	// Note: these options are aligned with those used (but not exposed) by github.com/veraison/go-cose
	cfg := CBORConfig{}

	if cfg.EncMode, err = encOpts.EncMode(); err != nil {
		return CBORConfig{}, err
	}

	if cfg.DecMode, err = decOpts.DecMode(); err != nil {
		return CBORConfig{}, err
	}

	decOpts.TagsMd = cbor.TagsForbidden
	if cfg.DecModeTagsForbidden, err = decOpts.DecMode(); err != nil {
		return CBORConfig{}, err
	}
	return cfg, nil
}
