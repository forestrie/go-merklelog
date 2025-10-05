package cose

import (
	"crypto/ecdsa"

	"github.com/ldclabs/cose/go/cwt"
	"github.com/veraison/go-cose"
)

// NewCNFClaim returns a CoseKey cnf claim formatted properly for the cose cwt
// claim label 13.  Note there is currently a minor divergence from the
// standard, we set "EC" rather than the more correct "EC2"
func NewCNFClaim(
	issuer string, subject string, kid string, alg cose.Algorithm,
	pub ecdsa.PublicKey) map[int64]interface{} {

	claim := map[int64]interface{}{
		CoseKeyLabel: map[int64]interface{}{
			KeyIDLabel: kid,
			// XXX: TODO: we perversly use the wrong name in go-datatrails-common in order to use jwk / json. We need to change that, at least so that EC2 is accepted and returned in the cose context
			KeyTypeLabel:   "EC", // EC2 is correct for rfc8152
			AlgorithmLabel: alg,
			ECCurveLabel:   pub.Curve.Params().Name,
			ECXLabel:       pub.X.Bytes(),
			ECYLabel:       pub.Y.Bytes(),
		},
	}
	return map[int64]interface{}{
		int64(cwt.KeyIss): issuer,
		int64(cwt.KeySub): subject,
		CNFLabel:          claim,
	}
}
