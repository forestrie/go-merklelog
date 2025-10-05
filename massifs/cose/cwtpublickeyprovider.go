package cose

import (
	"crypto"

	"github.com/veraison/go-cose"
)

type CWTPublicKeyProvider struct {
	cs *CoseSign1Message
}

func NewCWTPublicKeyProvider(cs *CoseSign1Message) *CWTPublicKeyProvider {
	return &CWTPublicKeyProvider{cs: cs}
}

func (p *CWTPublicKeyProvider) PublicKey() (crypto.PublicKey, cose.Algorithm, error) {
	protectedHeader := p.cs.Headers.Protected

	// get the algorithm
	algorithm, err := protectedHeader.Algorithm()
	if err != nil {
		// TODO: make an error specific to this and wrap it
		return nil, cose.Algorithm(0), err
	}

	// find the public key to verify the given message from
	//   the did in the protected header

	cwtClaims, err := p.cs.CWTClaimsFromProtectedHeader()
	if err != nil {
		return nil, cose.Algorithm(0), err
	}

	if cwtClaims.ConfirmationMethod == nil {
		return nil, cose.Algorithm(0), ErrCWTClaimsNoCNF
	}

	publicKey, err := cwtClaims.ConfirmationMethod.PublicKey()
	if err != nil {
		return nil, cose.Algorithm(0), err
	}

	return publicKey, algorithm, nil
}
