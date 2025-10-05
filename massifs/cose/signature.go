package cose

import (
	"github.com/fxamacker/cbor/v2"
)

/**
 * Holds all the signature information including the creation of the payload to be signed
 */

const (
	Sign1Context = "Signature1"
)

// CreateSignPayload creates a Sig_structure and returns it. As part of the cbor rfc, that is what needs
//
//	to be signed for cose sign1
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-4.4
//
// Code based off of: https://github.com/veraison/go-cose/blob/main/sign1.go#L156C69-L156C69 at commit from repo:
//
//	https://github.com/veraison/go-cose/commit/ed78bf9ee97cd30fd53fdb1900cce4096b71fc18
func (cs *CoseSign1Message) CreateSignPayload(external []byte) ([]byte, error) {

	var bodyProtected cbor.RawMessage
	bodyProtected, err := cs.Headers.MarshalProtected()
	if err != nil {
		return nil, err
	}

	// check we have a valid protected body
	err = cs.decMode.Wellformed(bodyProtected)
	if err != nil {
		return nil, err
	}

	// ensure external is initialised
	if external == nil {
		external = []byte{}
	}

	sigStructure := []interface{}{
		Sign1Context,  // context
		bodyProtected, // bodyProtected
		external,      // externalAAD
		cs.Payload,    // payload
	}

	// now encode it
	return cs.encMode.Marshal(sigStructure)
}
