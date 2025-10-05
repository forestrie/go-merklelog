package cose

import (
	"github.com/fxamacker/cbor/v2"
)

type SignOptions struct {
	encOpts *cbor.EncOptions
	decOpts *cbor.DecOptions
}

type SignOption func(*SignOptions)

func WithEncOptions(encOpts cbor.EncOptions) SignOption {
	return func(o *SignOptions) {
		o.encOpts = &cbor.EncOptions{}
		*o.encOpts = encOpts
	}
}

func WithDecOptions(decOpts cbor.DecOptions) SignOption {
	return func(o *SignOptions) {
		o.decOpts = &cbor.DecOptions{}
		*o.decOpts = decOpts
	}
}
