package massifs

import (
	commoncbor "github.com/datatrails/go-datatrails-common/cbor"
	"github.com/fxamacker/cbor/v2"
)

func NewCBORCodec() (commoncbor.CBORCodec, error) {
	codec, err := commoncbor.NewCBORCodec(EncOptions, DecOptions)
	if err != nil {
		return commoncbor.CBORCodec{}, err
	}
	return codec, nil
}

var (
	EncOptions = commoncbor.NewDeterministicEncOpts()
	DecOptions = cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF, // (default) duplicated key not allowed
		IndefLength: cbor.IndefLengthForbidden, // (default) no streaming
		// override the default decoding behaviour for unsigned integers to retain the sign
		IntDec: cbor.IntDecConvertNone, // decode CBOR uint/int to Go int64
		TagsMd: cbor.TagsForbidden,     // (default) no tags
	}
)
