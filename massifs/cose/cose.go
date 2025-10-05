// Package cose implements opinionated key types and ergonomics for veraisong/go-cose
package cose

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"io"
	"reflect"

	massifscbor "github.com/forestrie/go-merklelog/massifs/cbor"
	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/go/cwt"
	"github.com/veraison/go-cose"
)

/**
 * Cose functions based on CBOR Object Signing and Encryption (COSE)
 *
 * https://datatracker.ietf.org/doc/html/rfc8152
 */

const (
	HeaderLabelCWTClaimsDraft         int64 = 13
	HeaderLabelCWTClaims              int64 = 15
	HeaderLabelReceiptVersion         int64 = 390
	HeaderLabelDID                    int64 = 391
	HeaderLabelFeed                   int64 = 392
	HeaderLabelRegistrationPolicyInfo int64 = 393
)

// CoseSign1Message extends the cose.sign1message
type CoseSign1Message struct {
	*cose.Sign1Message
	decMode cbor.DecMode
	encMode cbor.EncMode
}

func newDefaultSignOptions() SignOptions {
	opts := SignOptions{
		// Fill in defaults
		encOpts: &cbor.EncOptions{},
		decOpts: &cbor.DecOptions{},
	}
	*opts.encOpts = massifscbor.NewDeterministicEncOpts()
	*opts.decOpts = massifscbor.NewDeterministicDecOptsConvertSigned()
	return opts
}

// NewCoseSign1Message creates a new cose sign1 message
func NewCoseSign1Message(message *cose.Sign1Message, withOpts ...SignOption) (*CoseSign1Message, error) {
	opts := newDefaultSignOptions()

	for _, o := range withOpts {
		o(&opts)
	}

	var err error

	csm := CoseSign1Message{
		Sign1Message: message,
	}

	csm.encMode, err = opts.encOpts.EncMode()
	if err != nil {
		return nil, err
	}

	csm.decMode, err = opts.decOpts.DecMode()
	if err != nil {
		return nil, err
	}

	return &csm, nil
}

// NewCoseSign1MessageFromCBOR creates a new cose sign1 message from a cbor encoded message
func NewCoseSign1MessageFromCBOR(message []byte, withOpts ...SignOption) (*CoseSign1Message, error) {
	opts := newDefaultSignOptions()

	for _, o := range withOpts {
		o(&opts)
	}

	coseMessage, err := UnmarshalCBOR(message)
	if err != nil {
		return nil, err
	}

	sign1Message := &CoseSign1Message{
		Sign1Message: coseMessage,
	}

	sign1Message.encMode, err = opts.encOpts.EncMode()
	if err != nil {
		return nil, err
	}

	sign1Message.decMode, err = opts.decOpts.DecMode()
	if err != nil {
		return nil, err
	}

	return sign1Message, nil
}

// MarshalCBOR marshals a cose_Sign1 message to cbor
func MarshalCBOR(message *cose.Sign1Message) ([]byte, error) {
	marshaledMessage, err := message.MarshalCBOR()
	if err != nil {
		return nil, err
	}

	return marshaledMessage, err
}

// UnmarshalCBOR unmarshals a cbor encoded cose_Sign1 message
func UnmarshalCBOR(message []byte) (*cose.Sign1Message, error) {
	var unmarshaledMessage cose.Sign1Message
	err := unmarshaledMessage.UnmarshalCBOR(message)
	if err != nil {
		return nil, err
	}

	return &unmarshaledMessage, err
}

// valueFromProtectedHeader gets a value from the cose_Sign1 protected Header given the label
func (cs *CoseSign1Message) valueFromProtectedHeader(label int64) (any, error) {
	header := cs.Headers.Protected

	value, ok := header[label]
	if !ok {
		return nil, &ErrNoProtectedHeaderValue{Label: label}
	}

	return value, nil
}

// ContentTypeFromProtectedheader gets the content type from the given protected header
func (cs *CoseSign1Message) ContentTypeFromProtectedheader() (string, error) {
	contentType, err := cs.valueFromProtectedHeader(cose.HeaderLabelContentType)
	if err != nil {
		return "", err
	}

	contentTypeStr, ok := contentType.(string)
	if !ok {
		return "", &ErrUnexpectedProtectedHeaderType{label: cose.HeaderLabelContentType, expectedType: "string", actualType: reflect.TypeOf(contentType).String()}
	}

	return contentTypeStr, nil
}

// DidFromProtectedHeader gets the DID (Decentralised IDentity)
//
//	to use to acquire the public key for verifying
func (cs *CoseSign1Message) DidFromProtectedHeader() (string, error) {
	did, err := cs.valueFromProtectedHeader(HeaderLabelDID)
	if err != nil {
		return "", err
	}

	didStr, ok := did.(string)
	if !ok {
		return "", &ErrUnexpectedProtectedHeaderType{label: HeaderLabelDID, expectedType: "string", actualType: reflect.TypeOf(did).String()}
	}

	return didStr, nil
}

// CWTClaimsFromProtectedHeader gets the CWT Claims from the protected header
func (cs *CoseSign1Message) CWTClaimsFromProtectedHeader() (*CWTClaims, error) {
	cwtClaimsRaw, err := cs.valueFromProtectedHeader(HeaderLabelCWTClaims)
	if err != nil {
		err2, ok := err.(*ErrNoProtectedHeaderValue)
		if !ok || err2.Label != HeaderLabelCWTClaims {
			return nil, err
		}
		cwtClaimsRaw, err = cs.valueFromProtectedHeader(HeaderLabelCWTClaimsDraft)
		if err != nil {
			return nil, err
		}
	}

	cwtClaimsMap, ok := cwtClaimsRaw.(map[any]any)
	if !ok {
		return nil, &ErrUnexpectedProtectedHeaderType{label: HeaderLabelCWTClaims, expectedType: "map[any]any", actualType: reflect.TypeOf(cwtClaimsMap).String()}
	}

	issuer, ok := cwtClaimsMap[int64(cwt.KeyIss)]
	if !ok {
		return nil, ErrCWTClaimsNoIssuer
	}

	issuerStr, ok := issuer.(string)
	if !ok {
		return nil, ErrCWTClaimsIssuerNotString
	}

	subject, ok := cwtClaimsMap[int64(cwt.KeySub)]
	if !ok {
		return nil, ErrCWTClaimsNoSubject
	}

	subjectStr, ok := subject.(string)
	if !ok {
		return nil, ErrCWTClaimsSubjectNotString
	}

	cwtClaims := CWTClaims{
		Issuer:  issuerStr,
		Subject: subjectStr,
	}

	// find verification key
	verificationKey, err := CNFCoseKey(cwtClaimsMap)
	if err != nil {
		// cnf is an optional field, so if we don't have one, log but don't error out
		if !errors.Is(err, ErrCWTClaimsNoCNF) {
			return nil, err
		}
	}

	if err == nil {
		cwtClaims.ConfirmationMethod = verificationKey
	}

	return &cwtClaims, nil
}

// FeedFromProtectedHeader gets the feed id from the protected header
func (cs *CoseSign1Message) FeedFromProtectedHeader() (string, error) {
	feed, err := cs.valueFromProtectedHeader(HeaderLabelFeed)
	if err != nil {
		return "", err
	}

	feedStr, ok := feed.(string)
	if !ok {
		return "", &ErrUnexpectedProtectedHeaderType{label: HeaderLabelFeed, expectedType: "string", actualType: reflect.TypeOf(feed).String()}
	}

	return feedStr, nil
}

// KidFromProtectedHeader gets the  kid from the protected header
func (cs *CoseSign1Message) KidFromProtectedHeader() (string, error) {
	kid, err := cs.valueFromProtectedHeader(cose.HeaderLabelKeyID)
	if err != nil {
		return "", err
	}

	kidBytes, ok := kid.([]byte)
	if !ok {
		return "", &ErrUnexpectedProtectedHeaderType{label: cose.HeaderLabelKeyID, expectedType: "[]byte", actualType: reflect.TypeOf(kid).String()}
	}

	return string(kidBytes), nil
}

type publicKeyProvider interface {
	PublicKey() (crypto.PublicKey, cose.Algorithm, error)
}

func (cs *CoseSign1Message) VerifyWithProvider(
	pubKeyProvider publicKeyProvider, external []byte,
) error {
	publicKey, algorithm, err := pubKeyProvider.PublicKey()
	if err != nil {
		return err
	}

	verifier, err := cose.NewVerifier(algorithm, publicKey)
	if err != nil {
		return err
	}

	// verify the message
	err = cs.Verify(external, verifier)
	if err != nil {
		return err
	}

	return nil
}

// VerifyWithCWTPublicKey verifies the given message using the public key
//
// found in the CWT Claims of the protected header
//
// https://ietf-wg-scitt.github.io/draft-ietf-scitt-architecture/draft-ietf-scitt-architecture.html
//
//		CWT_Claims = {
//		1 => tstr; iss, the issuer making statements,
//		2 => tstr; sub, the subject of the statements, (feed id)
//		/cnf/ 8 = > {
//		  /COSE_Key/ 1 :{
//			/kty/ 1 : /EC2/ 2,
//			/crv/ -1 : /P-256/ 1,
//			/x/ -2 : h'd7cc072de2205bdc1537a543d53c60a6acb62eccd890c7fa27c9
//					   e354089bbe13',
//			/y/ -3 : h'f95e1d4b851a2cc80fff87d8e23f22afb725d535e515d020731e
//					   79a3b4e47120'
//		   }
//		 }
//	 }
//		}
//
// NOTE: that iss needs to be set, as the user needs to trace the given public key back to an issuer.
func (cs *CoseSign1Message) VerifyWithCWTPublicKey(external []byte) error {
	return cs.VerifyWithProvider(NewCWTPublicKeyProvider(cs), external)
}

// VerifyWithPublicKey verifies the given message using the given public key
//
//	for verification
//
// example code:  https://github.com/veraison/go-cose/blob/main/example_test.go
func (cs *CoseSign1Message) VerifyWithPublicKey(publicKey crypto.PublicKey, external []byte) error {
	return cs.VerifyWithProvider(NewPublicKeyProvider(cs, publicKey), external)
}

// SignES256 signs a cose sign1 message using the given ecdsa private key using the algorithm ES256
func (cs *CoseSign1Message) SignES256(rand io.Reader, external []byte, privateKey *ecdsa.PrivateKey) error {
	signer, err := cose.NewSigner(cose.AlgorithmES256, privateKey)
	if err != nil {
		return err
	}

	if cs.Headers.Protected == nil {
		cs.Headers.Protected = make(cose.ProtectedHeader)
	}

	// Note: It *must* be ES256 to work with this types Verify etc. we could
	// detect the programming error where the caller has set the wrong alg but
	// that seems overly fussy.
	cs.Headers.Protected[cose.HeaderLabelAlgorithm] = cose.AlgorithmES256

	return cs.Sign(rand, external, signer)
}
