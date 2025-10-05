package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

const (
	mockDIDJson = `
	{
		"id": "did:web:app.dev-0.dev.jitsuin.io/archivist/v1/scitt",
		"@context": [
			"https://www.w3.org/ns/did/v1"
		],
		"verificationMethod": [
			{
				"id": "key-42",
				"type": "JsonWebkey",
				"controller": "did:web:app.dev-0.dev.jitsuin.io/archivist/v1/scitt",
				"publicKeyJwk": {
					"crv":"P-256",
					"kid":"idDrSXgK5zpuctVkmyRQusmP7F1V8C-6BvJL61p93H8",
					"kty":"EC",
					"x":"mQFR6En31DqP5HO6b_iJa-qJQuOd-l2cO5uRgzbw5kA",
					"y":"ynPrCc-5gDizkT4kVIFSvd7w0Y_EawL9-w5umDLiZMs",
					"alg": "ES256"
				}
			}
		]
	}
	`
)

// signP384 signs a given message using a one time use p256 curve ecdsa key
//
// NOTE: this is used to generate Known Answer Test (KAT) data
func signP384(data []byte) (string, error) {
	// create message header
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: cose.AlgorithmES384,
			HeaderLabelDID:            "did:web:app.dev--0.dev.jitsuin.io:archivist:v1:didweb",
			HeaderLabelFeed:           "foobar",
			cose.HeaderLabelKeyID:     []byte("scitt-counter-signing/d222f569a48c499ea614e3e3ee5d8253"),
		},
	}

	signature := []byte{88, 40, 191, 103, 109, 12, 12, 128, 172, 224, 180, 166, 223, 8, 147, 164, 79, 88, 191, 88, 204, 41, 10, 150, 153, 85, 187, 182, 241, 54, 35, 4, 81, 192, 234, 116, 233, 104, 240, 244, 44, 241, 149, 84, 179, 120, 94, 179, 35, 233, 244, 160, 167, 140, 41, 242, 228, 202, 4, 85, 142, 143, 191, 76, 227, 49, 162, 79, 112, 240, 78, 199, 172, 177, 201, 208, 75, 21, 111, 135, 129, 138, 244, 56, 194, 27, 40, 53, 10, 230, 128, 142, 133, 227, 34, 238}

	// sign and marshal message
	message := cose.Sign1Message{
		Headers:   headers,
		Signature: signature,
		Payload:   data,
	}

	messageCBOR, err := MarshalCBOR(&message)
	if err != nil {
		return "", err
	}

	// base 64 encode the message
	messageB64 := base64.StdEncoding.EncodeToString(messageCBOR)

	return messageB64, nil
}

// TestSignP256 tests:
//
// 1. we can generate a signed p256 cose message that is base64 encoded
func TestSignP256(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "positive",
			args: args{
				data: []byte("{\"foo\":\"bar\"}"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := signP384(test.args.data)

			assert.Nil(t, err)
			assert.NotNil(t, actual)
		})
	}
}

// Test_coseSign1Message_didFromProtectedHeader tests:
//
// 1. we can get a did from the protected header
// 2. if the did is not in the protected header, error
// 3. if the did is not a strng, error
func Test_coseSign1Message_didFromProtectedHeader(t *testing.T) {
	type fields struct {
		protectedHeader cose.ProtectedHeader
	}
	tests := []struct {
		name     string
		fields   fields
		expected string
		err      error
	}{
		{
			name: "positive",
			fields: fields{
				protectedHeader: cose.ProtectedHeader{
					HeaderLabelDID: "did:web:example.com",
				},
			},
			expected: "did:web:example.com",
			err:      nil,
		},
		{
			name: "no did in header",
			fields: fields{
				protectedHeader: cose.ProtectedHeader{},
			},
			expected: "",
			err:      &ErrNoProtectedHeaderValue{Label: HeaderLabelDID},
		},
		{
			name: "did not string",
			fields: fields{
				protectedHeader: cose.ProtectedHeader{
					HeaderLabelDID: 53,
				},
			},
			expected: "",
			err:      &ErrUnexpectedProtectedHeaderType{label: HeaderLabelDID, expectedType: "string", actualType: "int"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// make the message
			message := cose.Sign1Message{
				Headers: cose.Headers{
					Protected: test.fields.protectedHeader,
				},
			}

			cs := &CoseSign1Message{
				Sign1Message: &message,
			}

			actual, err := cs.DidFromProtectedHeader()

			assert.Equal(t, test.err, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}

// Test_coseSign1Message_feedFromProtectedHeader tests:
//
// 1. we can get a feed from the protected header
// 2. if the feed is not in the protected header, error
// 3. if the feed is not a strng, error
func Test_coseSign1Message_feedFromProtectedHeader(t *testing.T) {
	type fields struct {
		protectedHeader cose.ProtectedHeader
	}
	tests := []struct {
		name     string
		fields   fields
		expected string
		err      error
	}{
		{
			name: "positive",
			fields: fields{
				protectedHeader: cose.ProtectedHeader{
					HeaderLabelFeed: "pasta variants",
				},
			},
			expected: "pasta variants",
			err:      nil,
		},
		{
			name: "no feed in header",
			fields: fields{
				protectedHeader: cose.ProtectedHeader{},
			},
			expected: "",
			err:      &ErrNoProtectedHeaderValue{Label: HeaderLabelFeed},
		},
		{
			name: "did not string",
			fields: fields{
				protectedHeader: cose.ProtectedHeader{
					HeaderLabelFeed: 52,
				},
			},
			expected: "",
			err:      &ErrUnexpectedProtectedHeaderType{label: HeaderLabelFeed, expectedType: "string", actualType: "int"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// make the message
			message := cose.Sign1Message{
				Headers: cose.Headers{
					Protected: test.fields.protectedHeader,
				},
			}

			cs := &CoseSign1Message{
				Sign1Message: &message,
			}

			actual, err := cs.FeedFromProtectedHeader()

			assert.Equal(t, test.err, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}

// Test_coseSign1Message_kidFromProtectedHeader tests:
//
// 1. we can get a kid from the protected header
// 2. if the kid is not in the protected header, error
// 3. if the kid is not a []byte, error
func Test_coseSign1Message_kidFromProtectedHeader(t *testing.T) {
	type fields struct {
		protectedHeader cose.ProtectedHeader
	}
	tests := []struct {
		name     string
		fields   fields
		expected string
		err      error
	}{
		{
			name: "positive",
			fields: fields{
				protectedHeader: cose.ProtectedHeader{
					cose.HeaderLabelKeyID: []byte("im a key"),
				},
			},
			expected: "im a key",
			err:      nil,
		},
		{
			name: "no kid in header",
			fields: fields{
				protectedHeader: cose.ProtectedHeader{},
			},
			expected: "",
			err:      &ErrNoProtectedHeaderValue{Label: cose.HeaderLabelKeyID},
		},
		{
			name: "did not string",
			fields: fields{
				protectedHeader: cose.ProtectedHeader{
					cose.HeaderLabelKeyID: "oops im a string not byte slice",
				},
			},
			expected: "",
			err:      &ErrUnexpectedProtectedHeaderType{label: cose.HeaderLabelKeyID, expectedType: "[]byte", actualType: "string"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// make the message
			message := cose.Sign1Message{
				Headers: cose.Headers{
					Protected: test.fields.protectedHeader,
				},
			}

			cs := &CoseSign1Message{
				Sign1Message: &message,
			}

			actual, err := cs.KidFromProtectedHeader()

			assert.Equal(t, test.err, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}

// TestCoseSign1Message_VerifyWithPublicKey tests:
//
// 1. a one time generated public/private key we can verify the message
func TestCoseSign1Message_VerifyWithPublicKey(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "positive",
			err:  nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// create a signer
			privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.Nil(t, err)

			signer, err := cose.NewSigner(cose.AlgorithmES256, privateKey)
			require.Nil(t, err)

			// create message header
			headers := cose.Headers{
				Protected: cose.ProtectedHeader{
					cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
					391:                       "did:web:app.dev-0.dev.jitsuin.io:archivist:v1:scitt",
					392:                       "foobar",
					cose.HeaderLabelKeyID:     []byte("key-42"),
				},
			}

			// sign and marshal message
			messageCbor, err := cose.Sign1(rand.Reader, signer, headers, []byte("im the payload"), nil)
			require.Nil(t, err)

			message, err := NewCoseSign1MessageFromCBOR(messageCbor)
			require.Nil(t, err)

			err = message.VerifyWithPublicKey(privateKey.Public(), nil)

			assert.Equal(t, test.err, err)
		})
	}
}

// TestCoseSign1Message_CWTClaimsFromProtectedHeader tests:
//
// 1. a correctly formated CWT claims with verification key is given, return the claims as a map
// 2. a correctly formated CWT claims WITHOUT verification key is given, return the claims as a map
func TestCoseSign1Message_CWTClaimsFromProtectedHeader(t *testing.T) {
	type fields struct {
		Sign1Message *cose.Sign1Message
	}
	tests := []struct {
		name     string
		fields   fields
		expected *CWTClaims
		err      error
	}{
		{
			name: "positive, verification key",
			fields: fields{
				&cose.Sign1Message{
					Headers: cose.Headers{
						Protected: cose.ProtectedHeader{
							HeaderLabelCWTClaims: map[interface{}]interface{}{
								int64(1): "test-issuer",
								int64(2): "test-subject",
								int64(8): map[interface{}]interface{}{
									int64(1): map[interface{}]interface{}{
										int64(-1): "P-384",
										int64(2):  "testkey",
										int64(1):  "EC",
										int64(-2): []byte("QhPk3wbfLoowqrmOewzZVMtQSdC_pMUeOvVxQ7k1-Lojfv2n8buIhGw5znifNLMG"),
										int64(-3): []byte("AFxaZUbSjVR-qlRPX7WiU72xkkiFyjmautqOYm4BcPURpirIz4ySPTBXNDPQ2ZUW"),
									},
								},
							},
						},
					},
				},
			},
			expected: &CWTClaims{
				Issuer:  "test-issuer",
				Subject: "test-subject",
				ConfirmationMethod: &ECCoseKey{
					CoseCommonKey: &CoseCommonKey{
						Kty: "EC",
						Kid: []byte("testkey"),
					},
					Curve: "P-384",
					X:     []byte("QhPk3wbfLoowqrmOewzZVMtQSdC_pMUeOvVxQ7k1-Lojfv2n8buIhGw5znifNLMG"),
					Y:     []byte("AFxaZUbSjVR-qlRPX7WiU72xkkiFyjmautqOYm4BcPURpirIz4ySPTBXNDPQ2ZUW"),
				},
			},
			err: nil,
		},
		{
			name: "positive, no verification key",
			fields: fields{
				&cose.Sign1Message{
					Headers: cose.Headers{
						Protected: cose.ProtectedHeader{
							HeaderLabelCWTClaims: map[interface{}]interface{}{
								int64(1): "test-issuer",
								int64(2): "test-subject",
							},
						},
					},
				},
			},
			expected: &CWTClaims{
				Issuer:  "test-issuer",
				Subject: "test-subject",
			},
			err: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cs := &CoseSign1Message{
				Sign1Message: test.fields.Sign1Message,
			}
			actual, err := cs.CWTClaimsFromProtectedHeader()

			assert.Equal(t, test.expected, actual)
			assert.Equal(t, test.err, err)
		})
	}
}
