package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"reflect"
	"testing"

	"github.com/veraison/go-cose"
)

func TestCoseAlgForEC(t *testing.T) {
	type args struct {
		pub ecdsa.PublicKey
	}
	tests := []struct {
		name    string
		args    args
		want    cose.Algorithm
		wantErr bool
	}{
		{
			name: "P-256",
			args: args{
				pub: ecdsa.PublicKey{
					Curve: elliptic.P256(),
				},
			},
			want: cose.AlgorithmES256,
		},
		{
			name: "P-384",
			args: args{
				pub: ecdsa.PublicKey{
					Curve: elliptic.P384(),
				},
			},
			want: cose.AlgorithmES384,
		},
		{
			name: "P-521",
			args: args{
				pub: ecdsa.PublicKey{
					Curve: elliptic.P521(),
				},
			},
			want: cose.AlgorithmES512,
		},
		{
			name: "P-512 is not a valid curve name",
			args: args{
				pub: ecdsa.PublicKey{
					Curve: newBadCurve("P-512"),
				},
			},
			want:    0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CoseAlgForEC(tt.args.pub)
			if (err != nil) != tt.wantErr {
				t.Errorf("CoseAlgForEC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CoseAlgForEC() = %v, want %v", got, tt.want)
			}
		})
	}
}

func newBadCurve(name string) *badCurve {
	return &badCurve{name: name}
}

type badCurve struct {
	name string
}

func (c *badCurve) Params() *elliptic.CurveParams {
	params := elliptic.CurveParams{
		Name: c.name,
	}
	return &params
}

func (c *badCurve) IsOnCurve(x, y *big.Int) bool {
	return false
}

func (c *badCurve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	return nil, nil
}

func (c *badCurve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	return nil, nil
}

func (c *badCurve) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	return nil, nil
}

func (c *badCurve) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return nil, nil
}
