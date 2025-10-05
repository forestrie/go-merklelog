package cose

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/veraison/go-cose"
)

var (
	ErrCurveNotSupported = errors.New("curve not supported")
)

// CoseAlgForEC returns the appropraite algorithm for the provided public
// key curve or an error if the curve is not supported
//
// Noting that: "In order to promote interoperability, it is suggested that
// SHA-256 be used only with curve P-256, SHA-384 be used only with curve P-384,
// and SHA-512 be used with curve P-521." -- rfc 8152 & sec 4, 5480
func CoseAlgForEC(pub ecdsa.PublicKey) (cose.Algorithm, error) {

	switch pub.Curve.Params().Name {
	case "P-256":
		return cose.AlgorithmES256, nil
	case "P-384":
		return cose.AlgorithmES384, nil
	case "P-521":
		return cose.AlgorithmES512, nil
	default:
		return 0, fmt.Errorf("%s: %w", pub.Curve.Params().Name, ErrCurveNotSupported)
	}
}
