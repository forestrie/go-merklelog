package cose

import (
	"errors"
	"fmt"
)

var (
	ErrCWTClaimsNoIssuer  = errors.New("no issuer in cwt claims")
	ErrCWTClaimsNoSubject = errors.New("no subject in cwt claims")
	ErrCWTClaimsNoCNF     = errors.New("no cnf in cwt claims")

	ErrCWTClaimsIssuerNotString  = errors.New("issuer not string in cwt claims")
	ErrCWTClaimsSubjectNotString = errors.New("subject not string in cwt claims")
	ErrCWTClaimsCNFWrongFormat   = errors.New("cnf is in wrong format in cwt claims")

	ErrUnsupportedKey   = errors.New("unsupported key")
	ErrUnknownCurve     = errors.New("unknown curve")
	ErrUnknownKeyType   = errors.New("unknown keytype")
	ErrUnknownAlgorithm = errors.New("unknown algorithm")

	ErrMalformedRSAKey       = errors.New("rsa key not in expected format")
	ErrUnsupportedCNFKeyType = errors.New("unsupported keytype for cnf")
)

// ErrNoProtectedHeaderValue occurs when a cose protected header doesn't have a value for a given label
type ErrNoProtectedHeaderValue struct {

	// Label is the header Label that has no value
	Label int64
}

// Error implements the error interface
func (e *ErrNoProtectedHeaderValue) Error() string {
	return fmt.Sprintf("no value for protected header label: %v", e.Label)
}

// ErrUnexpectedProtectedHeaderType occurs when a cose protected header label value doesn't have the expected value type
type ErrUnexpectedProtectedHeaderType struct {

	// label is the header label
	label int64

	// actualType is the type of the value
	actualType string

	// expectedType is the type expected of the value
	expectedType string
}

// Error implements the error interface
func (e *ErrUnexpectedProtectedHeaderType) Error() string {
	return fmt.Sprintf("unexpected value type for protected header label: %v, expected: %v, got: %v", e.label, e.expectedType, e.actualType)
}

// ErrKeyValueError occurs when the key has unexpected values
type ErrKeyValueError struct {

	// field is the field that is unexpected
	field string

	// value is the value of the field
	value interface{}
}

// Error implements the error interface
func (e *ErrKeyValueError) Error() string {
	return fmt.Sprintf("unexpected value for key field: %v, value: %v", e.field, e.value)
}

// ErrKeyFormatError occurs when the key has unexpected format
type ErrKeyFormatError struct {

	// field is the field of the key with unexpected format
	field string

	// expectedType is the type expected of the value
	expectedType string

	// actualType is the actual type of the value
	actualType string
}

// Error implements the error interface
func (e *ErrKeyFormatError) Error() string {
	return fmt.Sprintf("unexpected format for key field: %v, expected type: %v, actual type: %v", e.field, e.expectedType, e.actualType)
}
