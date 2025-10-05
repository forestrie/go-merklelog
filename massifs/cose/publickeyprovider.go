package cose

import (
	"crypto"

	"github.com/veraison/go-cose"
)

type PublicKeyProvider struct {
	cs        *CoseSign1Message
	publicKey crypto.PublicKey
}

func NewPublicKeyProvider(cs *CoseSign1Message, publicKey crypto.PublicKey) *PublicKeyProvider {
	return &PublicKeyProvider{cs: cs, publicKey: publicKey}
}

func (p *PublicKeyProvider) PublicKey() (crypto.PublicKey, cose.Algorithm, error) {
	protectedHeader := p.cs.Headers.Protected

	// get the algorithm
	algorithm, err := protectedHeader.Algorithm()
	if err != nil {
		// TODO: make an error specific to this and wrap it
		return nil, cose.Algorithm(0), err
	}

	return p.publicKey, algorithm, nil
}
