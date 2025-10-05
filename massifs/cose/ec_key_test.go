package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNewECCoseKey tests:
//
// 1. A valid coseKey is given, succesfully creates a EC cose key
// 2. A cose Key missing keytype, error
// 3. A cose Key missing curve, error
// 4. A cose key missing x, error
// 5. A cose key missing y, error
// 6. A cose key with incorrect x format, error
// 7. A cose key with incorrect y format, error
// 8. A cose key with incorrect curve format, error
// 9. A cose key with incorrect keytype format, error
// 10. A cose key with unknown keytype, error
// 11. A cose key with unknown curve, error
func TestNewECCoseKey(t *testing.T) {
	type args struct {
		coseKey map[int64]any
	}
	tests := []struct {
		name     string
		args     args
		expected *ECCoseKey
		err      error
	}{
		{
			name: "positive",
			args: args{
				coseKey: map[int64]any{
					/*keytype*/ 1:/*EC2*/ int64(2),
					/*curve*/ -1:/*P-256*/ int64(1),
					/*x*/ -2: []byte("\xb3\xa0\xc4\xfa\xa7L\x01@\xc1\xcf\xcaR`s\\\x9bc\x19\xe7\x05C\x15{\xed\xab\xbc\xae0\xfa\xec}\x03"),
					/*y*/ -3: []byte(",\x89\xce\xb8\xf0J\xbbg\xac\x15\x12\xe4-\x12-U\x9d\xc8\xcb\x9cc;1\xd5\xe0 \x13\xbcmBT`"),
				},
			},
			expected: &ECCoseKey{
				CoseCommonKey: &CoseCommonKey{
					Kty: "EC",
				},
				Curve: "P-256",
				X:     []byte("\xb3\xa0\xc4\xfa\xa7L\x01@\xc1\xcf\xcaR`s\\\x9bc\x19\xe7\x05C\x15{\xed\xab\xbc\xae0\xfa\xec}\x03"),
				Y:     []byte(",\x89\xce\xb8\xf0J\xbbg\xac\x15\x12\xe4-\x12-U\x9d\xc8\xcb\x9cc;1\xd5\xe0 \x13\xbcmBT`"),
			},
			err: nil,
		},
		{
			name: "missing keytype",
			args: args{
				coseKey: map[int64]any{
					/*curve*/ -1:/*P-256*/ int64(1),
					/*x*/ -2: []byte("\xb3\xa0\xc4\xfa\xa7L\x01@\xc1\xcf\xcaR`s\\\x9bc\x19\xe7\x05C\x15{\xed\xab\xbc\xae0\xfa\xec}\x03"),
					/*y*/ -3: []byte(",\x89\xce\xb8\xf0J\xbbg\xac\x15\x12\xe4-\x12-U\x9d\xc8\xcb\x9cc;1\xd5\xe0 \x13\xbcmBT`"),
				},
			},
			expected: nil,
			err:      &ErrKeyValueError{field: "kty", value: nil},
		},
		{
			name: "missing curve",
			args: args{
				coseKey: map[int64]any{
					/*keytype*/ 1:/*EC2*/ int64(2),
					/*x*/ -2: []byte("\xb3\xa0\xc4\xfa\xa7L\x01@\xc1\xcf\xcaR`s\\\x9bc\x19\xe7\x05C\x15{\xed\xab\xbc\xae0\xfa\xec}\x03"),
					/*y*/ -3: []byte(",\x89\xce\xb8\xf0J\xbbg\xac\x15\x12\xe4-\x12-U\x9d\xc8\xcb\x9cc;1\xd5\xe0 \x13\xbcmBT`"),
				},
			},
			expected: nil,
			err:      &ErrKeyValueError{field: "crv", value: nil},
		},
		{
			name: "missing x",
			args: args{
				coseKey: map[int64]any{
					/*keytype*/ 1:/*EC2*/ int64(2),
					/*curve*/ -1:/*P-256*/ int64(1),
					/*y*/ -3: []byte(",\x89\xce\xb8\xf0J\xbbg\xac\x15\x12\xe4-\x12-U\x9d\xc8\xcb\x9cc;1\xd5\xe0 \x13\xbcmBT`"),
				},
			},
			expected: nil,
			err:      &ErrKeyValueError{field: "x", value: nil},
		},
		{
			name: "missing y",
			args: args{
				coseKey: map[int64]any{
					/*keytype*/ 1:/*EC2*/ int64(2),
					/*curve*/ -1:/*P-256*/ int64(1),
					/*x*/ -2: []byte("\xb3\xa0\xc4\xfa\xa7L\x01@\xc1\xcf\xcaR`s\\\x9bc\x19\xe7\x05C\x15{\xed\xab\xbc\xae0\xfa\xec}\x03"),
				},
			},
			expected: nil,
			err:      &ErrKeyValueError{field: "y", value: nil},
		},
		{
			name: "wrong format keytype",
			args: args{
				coseKey: map[int64]any{
					/*keytype*/ 1:/*EC2*/ int(2), // whoops int instead of int64
					/*curve*/ -1:/*P-256*/ int64(1),
					/*x*/ -2: []byte("\xb3\xa0\xc4\xfa\xa7L\x01@\xc1\xcf\xcaR`s\\\x9bc\x19\xe7\x05C\x15{\xed\xab\xbc\xae0\xfa\xec}\x03"),
					/*y*/ -3: []byte(",\x89\xce\xb8\xf0J\xbbg\xac\x15\x12\xe4-\x12-U\x9d\xc8\xcb\x9cc;1\xd5\xe0 \x13\xbcmBT`"),
				},
			},
			expected: nil,
			err:      &ErrKeyFormatError{expectedType: "[uint64|int64|string]", actualType: "int"},
		},
		{
			name: "wrong format curve",
			args: args{
				coseKey: map[int64]any{
					/*keytype*/ 1:/*EC2*/ int64(2),
					/*curve*/ -1:/*P-256*/ int(1), // whoops int instead of int64
					/*x*/ -2: []byte("\xb3\xa0\xc4\xfa\xa7L\x01@\xc1\xcf\xcaR`s\\\x9bc\x19\xe7\x05C\x15{\xed\xab\xbc\xae0\xfa\xec}\x03"),
					/*y*/ -3: []byte(",\x89\xce\xb8\xf0J\xbbg\xac\x15\x12\xe4-\x12-U\x9d\xc8\xcb\x9cc;1\xd5\xe0 \x13\xbcmBT`"),
				},
			},
			expected: nil,
			err:      &ErrKeyFormatError{expectedType: "[uint64|int64|string]", actualType: "int"},
		},
		{
			name: "wrong format x",
			args: args{
				coseKey: map[int64]any{
					/*keytype*/ 1:/*EC2*/ int64(2),
					/*curve*/ -1:/*P-256*/ int64(1),
					/*x*/ -2: "\xb3\xa0\xc4\xfa\xa7L\x01@\xc1\xcf\xcaR`s\\\x9bc\x19\xe7\x05C\x15{\xed\xab\xbc\xae0\xfa\xec}\x03", // whoops str instead of []byte
					/*y*/ -3: []byte(",\x89\xce\xb8\xf0J\xbbg\xac\x15\x12\xe4-\x12-U\x9d\xc8\xcb\x9cc;1\xd5\xe0 \x13\xbcmBT`"),
				},
			},
			expected: nil,
			err:      &ErrKeyFormatError{field: "x", expectedType: "[]byte", actualType: "string"},
		},
		{
			name: "wrong format x",
			args: args{
				coseKey: map[int64]any{
					/*keytype*/ 1:/*EC2*/ int64(2),
					/*curve*/ -1:/*P-256*/ int64(1),
					/*x*/ -2: []byte("\xb3\xa0\xc4\xfa\xa7L\x01@\xc1\xcf\xcaR`s\\\x9bc\x19\xe7\x05C\x15{\xed\xab\xbc\xae0\xfa\xec}\x03"),
					/*y*/ -3: ",\x89\xce\xb8\xf0J\xbbg\xac\x15\x12\xe4-\x12-U\x9d\xc8\xcb\x9cc;1\xd5\xe0 \x13\xbcmBT`", // whoops str instead of []byte
				},
			},
			expected: nil,
			err:      &ErrKeyFormatError{field: "y", expectedType: "[]byte", actualType: "string"},
		},
		{
			name: "unknown keytype",
			args: args{
				coseKey: map[int64]any{
					/*keytype*/ 1: int64(3252352),
					/*curve*/ -1:/*P-256*/ int64(1),
					/*x*/ -2: []byte("\xb3\xa0\xc4\xfa\xa7L\x01@\xc1\xcf\xcaR`s\\\x9bc\x19\xe7\x05C\x15{\xed\xab\xbc\xae0\xfa\xec}\x03"),
					/*y*/ -3: []byte(",\x89\xce\xb8\xf0J\xbbg\xac\x15\x12\xe4-\x12-U\x9d\xc8\xcb\x9cc;1\xd5\xe0 \x13\xbcmBT`"),
				},
			},
			expected: nil,
			err:      ErrUnknownKeyType,
		},
		{
			name: "unknown curve",
			args: args{
				coseKey: map[int64]any{
					/*keytype*/ 1:/*EC2*/ int64(2),
					/*curve*/ -1: int64(32526262),
					/*x*/ -2: []byte("\xb3\xa0\xc4\xfa\xa7L\x01@\xc1\xcf\xcaR`s\\\x9bc\x19\xe7\x05C\x15{\xed\xab\xbc\xae0\xfa\xec}\x03"),
					/*y*/ -3: []byte(",\x89\xce\xb8\xf0J\xbbg\xac\x15\x12\xe4-\x12-U\x9d\xc8\xcb\x9cc;1\xd5\xe0 \x13\xbcmBT`"),
				},
			},
			expected: nil,
			err:      ErrUnknownCurve,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := NewECCoseKey(test.args.coseKey)

			assert.Equal(t, test.err, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}

// TestECCoseKey_PublicKey tests:
//
// 1. a valid ec p-256 public key, returns a public key
// 2. a valid ec p-384 public key, returns a public key
// 3. a valid ec p-521 public key, returns a public key
// 4. a ec public key with nonsense curve, error
func TestECCoseKey_PublicKey(t *testing.T) {
	type fields struct {
		CoseCommonKey *CoseCommonKey
		Curve         string
		X             []byte
		Y             []byte
	}
	tests := []struct {
		name     string
		fields   fields
		expected crypto.PublicKey
		err      error
	}{
		{
			name: "positive P-256",
			fields: fields{
				CoseCommonKey: &CoseCommonKey{
					Kty: "EC",
				},
				Curve: "P-256",
				X:     []byte("1"),
				Y:     []byte("2"),
			},
			expected: &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     big.NewInt(49),
				Y:     big.NewInt(50),
			},
			err: nil,
		},
		{
			name: "positive P-384",
			fields: fields{
				CoseCommonKey: &CoseCommonKey{
					Kty: "EC",
				},
				Curve: "P-384",
				X:     []byte("1"),
				Y:     []byte("2"),
			},
			expected: &ecdsa.PublicKey{
				Curve: elliptic.P384(),
				X:     big.NewInt(49),
				Y:     big.NewInt(50),
			},
			err: nil,
		},
		{
			name: "positive P-521",
			fields: fields{
				CoseCommonKey: &CoseCommonKey{
					Kty: "EC",
				},
				Curve: "P-521",
				X:     []byte("1"),
				Y:     []byte("2"),
			},
			expected: &ecdsa.PublicKey{
				Curve: elliptic.P521(),
				X:     big.NewInt(49),
				Y:     big.NewInt(50),
			},
			err: nil,
		},
		{
			name: "nonsense curve",
			fields: fields{
				CoseCommonKey: &CoseCommonKey{
					Kty: "EC",
				},
				Curve: "curly wurly",
				X:     []byte("1"),
				Y:     []byte("2"),
			},
			expected: nil,
			err:      ErrUnknownCurve,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ecck := &ECCoseKey{
				CoseCommonKey: test.fields.CoseCommonKey,
				Curve:         test.fields.Curve,
				X:             test.fields.X,
				Y:             test.fields.Y,
			}

			actual, err := ecck.PublicKey()

			assert.Equal(t, test.err, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}
