// Package nitrite implements attestation verification for AWS Nitro Enclaves.
package nitrite

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// asserts/aws_nitro_enclaves.crt contains the PEM encoded roots for verifying Nitro
//	Enclave attestation signatures. You can download them from
//	https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
//	It's recommended you calculate the SHA256 sum of this string and match
//	it to the one supplied in the AWS documentation
//	https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html

//go:embed assets/aws_nitro_enclaves.crt
var AWSNitroEnclavesCertPEM []byte

// Document represents the AWS Nitro Enclave Attestation Document.
type Document struct {
	ModuleID    string          `cbor:"module_id" json:"module_id"`
	Timestamp   uint64          `cbor:"timestamp" json:"timestamp"`
	Digest      string          `cbor:"digest" json:"digest"`
	PCRs        map[uint][]byte `cbor:"pcrs" json:"pcrs"`
	Certificate []byte          `cbor:"certificate" json:"certificate"`
	CABundle    [][]byte        `cbor:"cabundle" json:"cabundle"`

	PublicKey []byte `cbor:"public_key" json:"public_key,omitempty"`
	UserData  []byte `cbor:"user_data" json:"user_data,omitempty"`
	Nonce     []byte `cbor:"nonce" json:"nonce,omitempty"`
}

func (d Document) CreatedAt() time.Time {
	if d.Timestamp == 0 {
		return time.Time{}
	}

	// Pg. 64 of https://docs.aws.amazon.com/pdfs/enclaves/latest/user/enclaves-user.pdf
	// describes Timestamp as "UTC time when document was created, in milliseconds"
	return time.UnixMilli(int64(d.Timestamp))
}

// Result is a successful verification result of an attestation payload.
type Result struct {
	// Document contains the attestation document.
	Document *Document `json:"document,omitempty"`

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

type CoseHeader struct {
	Alg interface{} `cbor:"1,keyasint,omitempty" json:"alg,omitempty"`
}

func (h *CoseHeader) AlgorithmString() (string, bool) {
	switch h.Alg.(type) {
	case string:
		return h.Alg.(string), true
	}

	return "", false
}

func (h *CoseHeader) AlgorithmInt() (int64, bool) {
	switch h.Alg.(type) {
	case int64:
		return h.Alg.(int64), true
	}

	return 0, false
}

type cosePayload struct {
	_ struct{} `cbor:",toarray"`

	Protected   []byte
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

type coseSignature struct {
	_ struct{} `cbor:",toarray"`

	Context     string
	Protected   []byte
	ExternalAAD []byte
	Payload     []byte
}

// Size of these fields (in bytes) comes from AWS Nitro documentation at
// https://docs.aws.amazon.com/enclaves/latest/user/enclaves-user.pdf
// from May 4, 2022.
// An experiment on 08/22/24 shows the following configuration is also possible
//
//	MaxUserDataLen  = 4050
//	MaxNonceLen     = 0
//	MaxPublicKeyLen = 0
const (
	MaxUserDataLen  = 1024
	MaxNonceLen     = MaxUserDataLen
	MaxPublicKeyLen = MaxUserDataLen
)

// Errors that are encountered when manipulating the COSESign1 structure.
var (
	ErrBadCOSESign1Structure          error = errors.New("Data is not a COSESign1 array")
	ErrCOSESign1EmptyProtectedSection error = errors.New("COSESign1 protected section is nil or empty")
	ErrCOSESign1EmptyPayloadSection   error = errors.New("COSESign1 payload section is nil or empty")
	ErrCOSESign1EmptySignatureSection error = errors.New("COSESign1 signature section is nil or empty")
	ErrCOSESign1BadAlgorithm          error = errors.New("COSESign1 algorithm not ECDSA384")
)

// Errors encountered when parsing the CoseBytes attestation document.
var (
	ErrBadAttestationDocument error = errors.New("Bad attestation document")
	ErrMandatoryFieldsMissing error = errors.New("One or more of mandatory fields missing")
	ErrBadDigest              error = errors.New("Payload 'digest' is not SHA384")
	ErrBadTimestamp           error = errors.New("Payload 'timestamp' is 0 or less")
	ErrBadPCRs                error = errors.New("Payload 'pcrs' is less than 1 or more than 32")
	ErrBadPCRIndex            error = errors.New("Payload 'pcrs' key index is not in [0, 32)")
	ErrBadPCRValue            error = errors.New("Payload 'pcrs' value is nil or not of length {32,48,64}")
	ErrBadCABundle            error = errors.New("Payload 'cabundle' has 0 elements")
	ErrBadCABundleItem        error = errors.New("Payload 'cabundle' has a nil item or of length not in [1, 1024]")
	ErrBadPublicKey           error = fmt.Errorf(
		"Payload 'public_key' length greater than %d",
		MaxPublicKeyLen,
	)
	ErrBadUserData error = fmt.Errorf(
		"Payload 'user_data' length greater than %d",
		MaxUserDataLen,
	)
	ErrBadNonce error = fmt.Errorf(
		"Payload 'nonce' length greater than %d",
		MaxNonceLen,
	)
	ErrBadCertificatePublicKeyAlgorithm error = errors.New("Payload 'certificate' has a bad public key algorithm (not ECDSA)")
	ErrBadCertificateSigningAlgorithm   error = errors.New("Payload 'certificate' has a bad public key signing algorithm (not ECDSAWithSHA384)")
	ErrBadSignature                     error = errors.New("Payload's signature does not match signature from certificate")
	ErrMarshallingCoseSignature         error = errors.New("Could not marshal COSE signature")
)

func createAWSNitroRoot() *x509.CertPool {
	pool := x509.NewCertPool()

	ok := pool.AppendCertsFromPEM(AWSNitroEnclavesCertPEM)
	if !ok {
		return nil
	}

	return pool
}

type RootCertFunc func() *x509.CertPool

func WithRootCert(pool *x509.CertPool) RootCertFunc {
	return func() *x509.CertPool {
		return pool
	}
}

func WithDefaultRootCert() RootCertFunc {
	return createAWSNitroRoot
}

type VerificationTimeFunc func(Document) time.Time

func WithTime(t time.Time) VerificationTimeFunc {
	return func(_ Document) time.Time {
		return t
	}
}

func WithAttestationTime() VerificationTimeFunc {
	return func(doc Document) time.Time {
		return doc.CreatedAt()
	}
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
func Verify(
	attestationBytes []byte,
	rootCert RootCertFunc,
	verificationTime VerificationTimeFunc,
) (*Result, error) {
	cose := cosePayload{}

	err := cbor.Unmarshal(attestationBytes, &cose)
	if nil != err {
		return nil, ErrBadCOSESign1Structure
	}

	if nil == cose.Protected || 0 == len(cose.Protected) {
		return nil, ErrCOSESign1EmptyProtectedSection
	}

	if nil == cose.Payload || 0 == len(cose.Payload) {
		return nil, ErrCOSESign1EmptyPayloadSection
	}

	if nil == cose.Signature || 0 == len(cose.Signature) {
		return nil, ErrCOSESign1EmptySignatureSection
	}

	header := CoseHeader{}
	err = cbor.Unmarshal(cose.Protected, &header)
	if nil != err {
		return nil, ErrBadCOSESign1Structure
	}

	intAlg, ok := header.AlgorithmInt()

	// https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
	if ok {
		switch intAlg {
		case -35:
			// do nothing -- OK

		default:
			return nil, ErrCOSESign1BadAlgorithm
		}
	} else {
		strAlg, ok := header.AlgorithmString()

		if ok {
			switch strAlg {
			case "ES384":
				// do nothing -- OK

			default:
				return nil, ErrCOSESign1BadAlgorithm
			}
		} else {
			return nil, ErrCOSESign1BadAlgorithm
		}
	}

	doc := Document{}

	err = cbor.Unmarshal(cose.Payload, &doc)
	if nil != err {
		return nil, ErrBadAttestationDocument
	}

	if "" == doc.ModuleID ||
		"" == doc.Digest ||
		0 == doc.Timestamp ||
		nil == doc.PCRs ||
		nil == doc.Certificate {
		return nil, ErrMandatoryFieldsMissing
	}

	if nil == doc.CABundle {
		return nil, ErrMandatoryFieldsMissing
	}

	if "SHA384" != doc.Digest {
		return nil, ErrBadDigest
	}

	if doc.Timestamp < 1 {
		return nil, ErrBadTimestamp
	}

	if len(doc.PCRs) < 1 || len(doc.PCRs) > 32 {
		return nil, ErrBadPCRs
	}

	for key, value := range doc.PCRs {
		if key > 31 {
			return nil, ErrBadPCRIndex
		}

		if nil == value ||
			!(32 == len(value) ||
				48 == len(value) ||
				64 == len(value) ||
				96 == len(value)) {
			return nil, ErrBadPCRValue
		}
	}

	if len(doc.CABundle) < 1 {
		return nil, ErrBadCABundle
	}

	for _, item := range doc.CABundle {
		if nil == item || len(item) < 1 || len(item) > 1024 {
			return nil, ErrBadCABundleItem
		}
	}

	if nil != doc.PublicKey && len(doc.PublicKey) > MaxPublicKeyLen {
		return nil, ErrBadPublicKey
	}
	if nil != doc.UserData && len(doc.UserData) > MaxUserDataLen {
		return nil, ErrBadUserData
	}
	if nil != doc.Nonce && len(doc.Nonce) > MaxNonceLen {
		return nil, ErrBadNonce
	}

	var certificates []*x509.Certificate
	certificates = make([]*x509.Certificate, 0, len(doc.CABundle)+1)

	cert, err := x509.ParseCertificate(doc.Certificate)
	if nil != err {
		return nil, err
	}

	if x509.ECDSA != cert.PublicKeyAlgorithm {
		return nil, ErrBadCertificatePublicKeyAlgorithm
	}

	if x509.ECDSAWithSHA384 != cert.SignatureAlgorithm {
		return nil, ErrBadCertificateSigningAlgorithm
	}

	certificates = append(certificates, cert)

	intermediates := x509.NewCertPool()

	for _, item := range doc.CABundle {
		cert, err := x509.ParseCertificate(item)
		if nil != err {
			return nil, err
		}

		intermediates.AddCert(cert)
		certificates = append(certificates, cert)
	}

	if verificationTime(doc).IsZero() {
		return nil, fmt.Errorf("verification time is 0")
	}

	_, err = cert.Verify(
		x509.VerifyOptions{
			Intermediates: intermediates,
			Roots:         rootCert(),
			CurrentTime:   verificationTime(doc),
			KeyUsages: []x509.ExtKeyUsage{
				x509.ExtKeyUsageAny,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("verifying certificate: %w", err)
	}

	coseSig := coseSignature{
		Context:     "Signature1",
		Protected:   cose.Protected,
		ExternalAAD: []byte{},
		Payload:     cose.Payload,
	}

	sigStruct, err := cbor.Marshal(&coseSig)
	if err != nil {
		return nil, ErrMarshallingCoseSignature
	}

	signatureOk := checkECDSASignature(
		cert.PublicKey.(*ecdsa.PublicKey),
		sigStruct,
		cose.Signature,
	)

	if !signatureOk {
		err = ErrBadSignature
	}

	return &Result{
		Document:     &doc,
		Certificates: certificates,
		Protected:    cose.Protected,
		Unprotected:  cose.Unprotected,
		Payload:      cose.Payload,
		Signature:    cose.Signature,
		SignatureOK:  signatureOk,
		COSESign1:    sigStruct,
	}, err
}

func checkECDSASignature(
	publicKey *ecdsa.PublicKey,
	sigStruct, signature []byte,
) bool {
	// https://datatracker.ietf.org/doc/html/rfc8152#section-8.1

	var hashSigStruct []byte = nil

	switch publicKey.Curve.Params().Name {
	case "P-224":
		h := sha256.Sum224(sigStruct)
		hashSigStruct = h[:]

	case "P-256":
		h := sha256.Sum256(sigStruct)
		hashSigStruct = h[:]

	case "P-384":
		h := sha512.Sum384(sigStruct)
		hashSigStruct = h[:]

	case "P-512":
		h := sha512.Sum512(sigStruct)
		hashSigStruct = h[:]

	default:
		panic(
			fmt.Sprintf(
				"unknown ECDSA curve name %v",
				publicKey.Curve.Params().Name,
			),
		)
	}

	if len(signature) != 2*len(hashSigStruct) {
		return false
	}

	r := big.NewInt(0)
	s := big.NewInt(0)

	r = r.SetBytes(signature[:len(hashSigStruct)])
	s = s.SetBytes(signature[len(hashSigStruct):])

	return ecdsa.Verify(publicKey, hashSigStruct, r, s)
}
