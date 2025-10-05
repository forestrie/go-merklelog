package cbor

import "github.com/fxamacker/cbor/v2"

// CBORCodec encode decode
type CBORCodec struct {
	cborCfg CBORConfig
}

func NewCBORCodec(encOpts cbor.EncOptions, decOpts cbor.DecOptions) (CBORCodec, error) {
	var err error

	kce := CBORCodec{}
	if kce.cborCfg, err = NewCBORConfig(encOpts, decOpts); err != nil {
		return CBORCodec{}, err
	}
	return kce, err
}

func (kce *CBORCodec) MarshalCBOR(value any) ([]byte, error) {
	return kce.cborCfg.EncMode.Marshal(value)
}

func (kce *CBORCodec) UnmarshalCBOR(value []byte) ([]any, error) {
	decoded := []any{}
	err := kce.cborCfg.DecMode.Unmarshal(value, &decoded)

	return decoded, err
}
func (kce *CBORCodec) UnmarshalInto(b []byte, decoded interface{}) error {
	return kce.cborCfg.DecMode.Unmarshal(b, decoded)
}
