package cose

import (
	"crypto"
	"crypto/rsa"
	"math/big"
)

/**
 * Cose RSA Key as defined in: https://www.rfc-editor.org/rfc/rfc8152.html#page-33
 */

// RSACoseKey is an RSA cose key
type RSACoseKey struct {
	*CoseCommonKey

	N int64 `json:"n,omitempty"`
	E int64 `json:"e,omitempty"`
}

// NewRSACoseKey creates a new RSA cose key
func NewRSACoseKey(coseKey map[int64]interface{}) (*RSACoseKey, error) {
	coseCommonKey, err := NewCoseCommonKey(coseKey)
	if err != nil {
		return nil, err
	}

	n, ok := coseKey[RSANLabel]
	if !ok {
		return nil, ErrMalformedRSAKey
	}

	e, ok := coseKey[RSAELabel]
	if !ok {
		return nil, ErrMalformedRSAKey
	}

	// TODO: errhandling
	eInt64, _ := e.(int64)
	nInt64, _ := n.(int64)

	rsaCoseKey := RSACoseKey{
		CoseCommonKey: coseCommonKey,
		E:             eInt64,
		N:             nInt64,
	}

	return &rsaCoseKey, nil
}

// PublicKey gets the public key from the
//
//	RSACoseKey
func (rsack *RSACoseKey) PublicKey() (crypto.PublicKey, error) {
	publicKey := rsa.PublicKey{}

	// now find n & e values
	n := big.NewInt(rsack.N)

	// note: this is rounding down in size from int64, worst case if E is too large
	//       verification will fail
	e := int(rsack.E)

	publicKey.N = n
	publicKey.E = e

	return &publicKey, nil
}
