package cose

import (
	"crypto"
	"fmt"
	"reflect"
)

/**
 * Cose Key as defined in: https://www.rfc-editor.org/rfc/rfc8152.html#page-33
 */

const (
	KeyTypeLabel       = 1
	KeyIDLabel         = 2
	AlgorithmLabel     = 3
	KeyOperationsLabel = 4

	KeyTypeOKP = int64(1)
	KeyTypeEC2 = int64(2)
	KeyTypeRSA = int64(3)

	KeyOperationVerifyLabel = 2

	ECCurveLabel = -1
	ECXLabel     = -2
	ECYLabel     = -3
	ECDLabel     = -4

	RSANLabel = -1
	RSAELabel = -2
	RSADLabel = -3
	RSAPLabel = -4
	RSAQLabel = -5
)

// CoseKey interface as defined in:
//
//	https://www.rfc-editor.org/rfc/rfc8152.html#page-33
//
// allows the retrieval of common properties as well as the public key half
type CoseKey interface {
	Algorithm() string
	KeyID() []byte
	KeyType() string
	KeyOperations() []string

	PublicKey() (crypto.PublicKey, error)
}

// CoseCommonKey as defined in:
//
//	https://www.rfc-editor.org/rfc/rfc8152.html#page-33
//
//	COSE_Key = {
//		1 => tstr / int,          ; kty
//		? 2 => bstr,              ; kid
//		? 3 => tstr / int,        ; alg
//		? 4 => [+ (tstr / nt) ], ; key_ops
//		? 5 => bstr,              ; Base IV
//		* label => values
//	}
//
// Only with the common fields
type CoseCommonKey struct {
	// Key Type
	Kty string `json:"kty,omitempty"`

	// Key Identity
	Kid []byte `json:"kid,omitempty"`

	// Algorithm for cryptographic operations using the key
	Alg string `json:"alg,omitempty"`

	// Allowed cryptographic operations using the key
	KeyOps []string `json:"key_ops,omitempty"`
}

func decodeInt64LabelOrString(label any) (int64, string, error) {
	var s string
	var i64 int64
	var u64 uint64

	s, ok := label.(string)
	if ok {
		return 0, s, nil
	}
	i64, ok = label.(int64)
	if ok {
		return i64, "", nil
	}

	u64, ok = label.(uint64)
	if ok {
		return int64(u64), "", nil
	}
	return 0, "", &ErrKeyFormatError{expectedType: "[uint64|int64|string]", actualType: reflect.TypeOf(label).String()}
}

func decodeInt64Label(label any) (int64, error) {
	var i64 int64
	var u64 uint64

	i64, ok := label.(int64)
	if ok {
		return i64, nil
	}

	u64, ok = label.(uint64)
	if ok {
		return int64(u64), nil
	}
	return 0, &ErrKeyFormatError{expectedType: "[uint64|int64|string]", actualType: reflect.TypeOf(label).String()}
}

func decodeBytes(label any) ([]byte, error) {
	b, ok := label.([]byte)
	if ok {
		return b, nil
	}

	s, ok := label.(string)
	if ok {
		return []byte(s), nil
	}
	return b, nil
}

// NewCoseCommonKey creates a new cose key with common fields
func NewCoseCommonKey(coseKey map[int64]any) (*CoseCommonKey, error) {
	keytype, err := KeyTypeLabelToKeyType(coseKey[KeyTypeLabel])
	if err != nil {
		return nil, err
	}

	algoritm, err := AlgorithmLabelToAlgorithm(coseKey[AlgorithmLabel])
	if err != nil {
		// algorithm is an optional field, we do not need it
		//  so don't error out, just log and set to empty
		algoritm = ""
	}

	kid, err := decodeBytes(coseKey[KeyIDLabel])
	if err != nil {
		return nil, err
	}

	keyOps := coseKey[KeyOperationsLabel]
	// TODO: error handling
	keyOpsList, _ := keyOps.([]string)

	coseCommonKey := CoseCommonKey{
		Kty:    keytype,
		Alg:    algoritm,
		Kid:    kid,
		KeyOps: keyOpsList,
	}

	return &coseCommonKey, nil
}

// Algorithm returns the algorithm the key uses
func (cck *CoseCommonKey) Algorithm() string {
	return cck.Alg
}

// KeyType returns the keytype of the key
func (cck *CoseCommonKey) KeyType() string {
	return cck.Kty
}

// KeyID returns the key identity of the key
func (cck *CoseCommonKey) KeyID() []byte {
	return cck.Kid
}

// KeyOperations returns the allowed key operation for the key
func (cck *CoseCommonKey) KeyOperations() []string {
	return cck.KeyOps
}

// AlgorithmLabelToAlgorithm converts the cose key alg label (string or int64)
//
//	to a string algorithm name.
//
// Mapping defined: https://www.rfc-editor.org/rfc/rfc8152.html#page-73
func AlgorithmLabelToAlgorithm(label any) (string, error) {
	if label == nil {
		return "", &ErrKeyValueError{field: "alg", value: nil}
	}

	algi, algs, err := decodeInt64LabelOrString(label)
	if err != nil {
		return "", err
	}
	// first check if the label is already a string
	if algs != "" {
		return algs, nil
	}

	switch algi {
	case -7:
		return "ES256", nil
	case -35:
		return "ES384", nil
	case -36:
		return "ES512", nil
	case -8:
		return "EdDSA", nil
	case -65535:
		return "RS1", nil
	case -259:
		return "RS512", nil
	case -258:
		return "RS384", nil
	case -257:
		return "RS256", nil
	}

	return "", ErrUnknownAlgorithm
}

// CurveLabelToCurve converts the cose key crv label (string or int64)
//
//	to a string curve name.
//
// Mapping defined: https://www.rfc-editor.org/rfc/rfc8152.html#page-73
func CurveLabelToCurve(label any) (string, error) {
	if label == nil {
		return "", &ErrKeyValueError{field: "crv", value: nil}
	}

	curvi, curv, err := decodeInt64LabelOrString(label)
	if err != nil {
		return "", err
	}
	// first check if the label is already a string
	if curv != "" {
		return curv, nil
	}

	// TODO: PyCose does not accept P-256, only P_256. Resolve which is correct.
	switch curvi {
	case 1:
		return "P-256", nil
	case 2:
		return "P-384", nil
	case 3:
		return "P-521", nil
	case 4:
		return "X25519", nil
	case 5:
		return "X448", nil
	case 6:
		return "Ed25519", nil
	case 7:
		return "Ed448", nil
	}

	return "", ErrUnknownCurve
}

// KeyTypeLabelToKeyType converts the cose key type label (int64 or string)
//
//	to a string keytype name.
//
// Mapping defined: https://www.rfc-editor.org/rfc/rfc8152.html#page-73
func KeyTypeLabelToKeyType(label any) (string, error) {
	if label == nil {
		return "", &ErrKeyValueError{field: "kty", value: nil}
	}

	kti, kts, err := decodeInt64LabelOrString(label)
	if err != nil {
		return "", err
	}
	if kts != "" {
		return kts, nil
	}

	switch kti {
	case 1:
		return "OKP", nil
	case 2:
		// we use jwk atm to convert the json cose_key into a crypto.Publickey
		//  the only difference being EC keys are called EC2 for cose_key and EC for jwk
		return "EC", nil
	case 3:
		return "RSA", nil
	}

	return "", ErrUnknownKeyType
}

// convertKeysToLabels converts all keys in the map to int64 cose labels
func convertKeysToLabels(coseKey map[any]any) (map[int64]any, error) {
	labelsMap := map[int64]any{}

	for key, value := range coseKey {

		label, err := decodeInt64Label(key)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCWTClaimsCNFWrongFormat, err)
		}

		labelsMap[label] = value
	}

	return labelsMap, nil
}
