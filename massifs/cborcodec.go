package massifs

import (
	"github.com/forestrie/go-merklelog/massifs/cbor"
)

func NewCBORCodec() (cbor.CBORCodec, error) {
	codec, err := cbor.NewCBORCodec(cbor.EncOptions, cbor.DecOptions)
	if err != nil {
		return cbor.CBORCodec{}, err
	}
	return codec, nil
}
