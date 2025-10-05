package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

func mustGenerateECKey(t *testing.T, curve elliptic.Curve) ecdsa.PrivateKey {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	return *privateKey
}

func TestNewCNFClaim(t *testing.T) {
	type args struct {
		issuer  string
		subject string
		kid     string
		curve   elliptic.Curve
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
		{"ok", args{
			issuer:  "test.datatrails",
			subject: "test.datatrails",
			kid:     "kid.test.datatrails",
			curve:   elliptic.P256(),
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := mustGenerateECKey(t, tt.args.curve)
			alg, err := CoseAlgForEC(key.PublicKey)
			require.NoError(t, err)
			signer, err := cose.NewSigner(alg, &key)
			require.Nil(t, err)

			// create the claim
			cnfClaim := NewCNFClaim(tt.args.issuer, tt.args.subject, tt.args.kid, alg, key.PublicKey)

			// sign and marshal message
			headers := cose.Headers{
				Protected: cose.ProtectedHeader{
					HeaderLabelCWTClaims: cnfClaim,
				},
			}

			messageCbor, err := cose.Sign1(rand.Reader, signer, headers, []byte("im the payload"), nil)
			require.Nil(t, err)

			// We have extensive tests showing that CWTClaimsFromProtectedHeader
			// catches malformed cnf, so here we just lean on that to check we
			// have produced a properly formatted claim. But we need to round
			// trip to get things in the form that method expects.

			// check what we get back from the decoder is correct
			msg, err := NewCoseSign1MessageFromCBOR(messageCbor)
			require.Nil(t, err)

			_, err = msg.CWTClaimsFromProtectedHeader()
			assert.NoError(t, err)
		})
	}
}
