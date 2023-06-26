// Package nitrite implements attestation verification for AWS Nitro Enclaves.
package nitrite

import (
	"crypto/x509"
	"time"

	"github.com/blocky/nitrite/internal/attestation"
	"github.com/blocky/nitrite/internal/cose"
)

// Result is a successful verification result of an attestation payload.
type Result struct {
	// Document contains the attestation document.
	Document *attestation.Document `json:"document,omitempty"`

	// Certificates contains all of the certificates except the root.
	Certificates []*x509.Certificate `json:"certificates,omitempty"`

	// Protected section from the COSE Sign1 payload.
	Protected []byte `json:"protected,omitempty"`
	// Unprotected section from the COSE Sign1 payload.
	Unprotected []byte `json:"unprotected,omitempty"`
	// Payload section from the COSE Sign1 payload.
	Payload []byte `json:"payload,omitempty"`
	// Signature section from the COSE Sign1 payload.
	Signature []byte `json:"signature,omitempty"`

	// SignatureOK designates if the signature was OK (but certificate could be
	// invalid, not trusted, expired, etc.)
	SignatureOK bool `json:"signature_ok"`

	// COSESign1 contains the COSE Signature Structure which was used to
	// calculate the `Signature`.
	COSESign1 []byte `json:"cose_sign1,omitempty"`
}

// VerifyOptions specifies the options for verifying the attestation payload.
// If `Roots` is nil, the `DefaultCARoot` is used. If `CurrentTime` is 0,
// `time.Now()` will be used. It is a strong recommendation you explicitly
// supply this value.
type VerifyOptions struct {
	Roots               *x509.CertPool
	CurrentTime         time.Time
	AllowSelfSignedCert bool
}

// Verify verifies the attestation payload from `data` with the provided
// verification options. If the options specify `Roots` as `nil`, the
// `DefaultCARoot` will be used. If you do not specify `CurrentTime`,
// `time.Now()` will be used. It is strongly recommended you specifically
// supply the time.  If the returned error is non-nil, it is either one of the
// `Err` codes specified in this package, or is an error from the `crypto/x509`
// package. Revocation checks are NOT performed and you should check for
// revoked certificates by looking at the `Certificates` field in the `Result`.
// Result will be non-null if and only if either of these are true: certificate
// verification has passed, certificate verification has failed (expired, not
// trusted, etc.), signature is OK or signature is not OK. If either signature
// is not OK or certificate can't be verified, both Result and error will be
// set! You can use the SignatureOK field from the result to distinguish
// errors.
// TODO use fuzz testing for helper functions when passing data byte arrays to see if we can generate
// TODO unit test different paths for nitrite Verify() based on options passed in
func Verify(data []byte, options VerifyOptions) (*Result, error) {
	cosePayload, err := cose.ExtractCosePayload(data)
	if err != nil {
		return nil, err
	}
	err = cose.VerifyCosePayload(cosePayload)
	if err != nil {
		return nil, err
	}

	coseHeader, err := cose.ExtractCoseHeader(cosePayload)
	if err != nil {
		return nil, err
	}
	err = cose.VerifyCoseHeader(coseHeader)
	if err != nil {
		return nil, err
	}

	doc, err := cose.ExtractAttestationDoc(cosePayload)
	if err != nil {
		return nil, err
	}
	err = attestation.VerifyAttestationDoc(doc, options.AllowSelfSignedCert)
	if err != nil {
		return nil, err
	}

	cert, certificates, intermediates, err := attestation.ExtractCertificates(
		doc,
		options.AllowSelfSignedCert,
	)
	if err != nil {
		return nil, err
	}
	err = attestation.VerifyCertificates(
		cert,
		intermediates,
		options.Roots,
		options.CurrentTime,
	)
	if err != nil {
		return nil, err
	}

	sign1, err := cose.VerifyCoseSign1(cosePayload, cert)
	if err != nil {
		return nil, err
	}

	return &Result{
		Document:     &doc,
		Certificates: certificates,
		Protected:    cosePayload.Protected,
		Unprotected:  cosePayload.Unprotected,
		Payload:      cosePayload.Payload,
		Signature:    cosePayload.Signature,
		SignatureOK:  true,
		COSESign1:    sign1,
	}, err
}
