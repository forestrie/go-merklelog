package cose

/**
 * CBOR Web Token (CWT) https://www.rfc-editor.org/rfc/rfc8392.html
 *
 * with the minimal set of claims laid out in: https://ietf-wg-scitt.github.io/draft-ietf-scitt-architecture/draft-ietf-scitt-architecture.html
 *
 * CWT_Claims = {
 * 1 => tstr; iss, the issuer making statements,
 * 2 => tstr; sub, the subject of the statements,
 * * tstr => any
 * }
 *
 */

const (
	// Confirmation Method Label
	CNFLabel = int64(8)

	CoseKeyLabel = int64(1)
)

// CWTClaims are the cwt claims found on the protected header of a signed SCITT statement:
// https://ietf-wg-scitt.github.io/draft-ietf-scitt-architecture/draft-ietf-scitt-architecture.html
type CWTClaims struct {
	Issuer             string  `json:"1,omitempty"`
	Subject            string  `json:"2,omitempty"`
	ConfirmationMethod CoseKey `json:"8,omitempty"`
}

// CNFCoseKey gets the cose key from the CNF field of CWT_Claims if it exists
//
// expected format is:
//
//	 /cnf/ 8 :{
//		/COSE_Key/ 1 :{
//			/kty/ 1 : /EC2/ 2,
//			/crv/ -1 : /P-256/ 1,
//			/x/ -2 : h'd7cc072de2205bdc1537a543d53c60a6acb62eccd890c7fa27c9
//					   e354089bbe13',
//			/y/ -3 : h'f95e1d4b851a2cc80fff87d8e23f22afb725d535e515d020731e
//					   79a3b4e47120'
//		   }
//		 }
func CNFCoseKey(cwtClaimsMap map[interface{}]interface{}) (CoseKey, error) {
	cnf, ok := cwtClaimsMap[CNFLabel]
	if !ok {
		return nil, ErrCWTClaimsNoCNF
	}

	// expect cnf to be a map[interface{}]interface{}
	cnfMap, ok := cnf.(map[interface{}]interface{})
	if !ok {
		return nil, ErrCWTClaimsCNFWrongFormat
	}

	// expect to have the cose_key label
	confirmationKey := cnfMap[CoseKeyLabel]

	confirmationKeyMap, ok := confirmationKey.(map[interface{}]interface{})
	if !ok {
		return nil, ErrCWTClaimsCNFWrongFormat
	}

	coseKeyMap, err := convertKeysToLabels(confirmationKeyMap)
	if err != nil {
		return nil, err
	}

	keytype, err := KeyTypeLabelToKeyType(coseKeyMap[KeyTypeLabel])
	if err != nil {
		return nil, err
	}

	var coseKey CoseKey
	switch keytype {
	case "EC":
		coseKey, err = NewECCoseKey(coseKeyMap)
	case "RSA":
		// TODO: add rsa support if needed
		return nil, ErrUnsupportedCNFKeyType
	default:
		return nil, ErrUnknownKeyType
	}

	return coseKey, err
}
