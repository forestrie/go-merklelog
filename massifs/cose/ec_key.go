package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"reflect"
)

/**
 * Cose EC Key as defined in: https://www.rfc-editor.org/rfc/rfc8152.html#page-33
 */

// ECCoseKey is an EC2 cose key
type ECCoseKey struct {
	*CoseCommonKey

	Curve string `json:"crv,omitempty"`
	X     []byte `json:"x,omitempty"`
	Y     []byte `json:"y,omitempty"`
}

// NewECCoseKey creates a new EC Cose Key
func NewECCoseKey(coseKey map[int64]any) (*ECCoseKey, error) {
	coseCommonKey, err := NewCoseCommonKey(coseKey)
	if err != nil {
		return nil, err
	}

	curve, err := CurveLabelToCurve(coseKey[ECCurveLabel])
	if err != nil {
		return nil, err
	}

	x, ok := coseKey[ECXLabel]
	if !ok {
		return nil, &ErrKeyValueError{field: "x", value: nil}
	}

	y, ok := coseKey[ECYLabel]
	if !ok {
		return nil, &ErrKeyValueError{field: "y", value: nil}
	}

	xBytes, ok := x.([]byte)
	if !ok {
		return nil, &ErrKeyFormatError{field: "x", expectedType: "[]byte", actualType: reflect.TypeOf(x).String()}
	}

	yBytes, ok := y.([]byte)
	if !ok {
		return nil, &ErrKeyFormatError{field: "y", expectedType: "[]byte", actualType: reflect.TypeOf(y).String()}
	}

	ecCoseKey := ECCoseKey{
		CoseCommonKey: coseCommonKey,
		Curve:         curve,
		X:             xBytes,
		Y:             yBytes,
	}

	return &ecCoseKey, nil
}

// PublicKey gets the public key from the
//
//	ECCoseKey
func (ecck *ECCoseKey) PublicKey() (crypto.PublicKey, error) {
	publicKey := ecdsa.PublicKey{}

	// first find the curve
	switch ecck.Curve {
	case "P-256":
		publicKey.Curve = elliptic.P256()
	case "P-384":
		publicKey.Curve = elliptic.P384()
	case "P-521":
		publicKey.Curve = elliptic.P521()
	default:
		return nil, ErrUnknownCurve
	}

	// now find x & y values
	x := big.NewInt(0)
	x = x.SetBytes(ecck.X)

	y := big.NewInt(0)
	y = y.SetBytes(ecck.Y)

	publicKey.X = x
	publicKey.Y = y

	return &publicKey, nil
}

func (ecck *ECCoseKey) KeyID() []byte {
	return ecck.Kid
}
