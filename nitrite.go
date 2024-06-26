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

// VerifyOptions specifies the options for verifying the attestation payload.
// If `Roots` is nil, the `DefaultCARoot` is used. If `CurrentTime` is 0,
// `time.Now()` will be used. It is a strong recommendation you explicitly
// supply this value.
type VerifyOptions struct {
	Roots               *x509.CertPool
	CurrentTime         time.Time
	AllowSelfSignedCert bool
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

type CosePayload struct {
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
// With maxNonceLen = 1024, maxUserDataLen = 1024, and maxPublicKeyLen = 1024
// the total AttestationLen = 6591.
// An experiment on August 8, 2022, allowed user data to be maximized to
// maxUserDataLen = 3868 with maxNonceLen = 40 and maxPublicKeyLen = 1024 for
// the total AttestationLen = 8451.
const (
	maxNonceLen       = 1024
	maxUserDataLen    = 2048
	maxPublicKeyLen   = 1024
	MaxAttestationLen = 6591
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
		maxPublicKeyLen,
	)
	ErrBadUserData error = fmt.Errorf(
		"Payload 'user_data' length greater than %d",
		maxUserDataLen,
	)
	ErrBadNonce error = fmt.Errorf(
		"Payload 'nonce' length greater than %d",
		maxNonceLen,
	)
	ErrBadCertificatePublicKeyAlgorithm error = errors.New("Payload 'certificate' has a bad public key algorithm (not ECDSA)")
	ErrBadCertificateSigningAlgorithm   error = errors.New("Payload 'certificate' has a bad public key signing algorithm (not ECDSAWithSHA384)")
	ErrBadSignature                     error = errors.New("Payload's signature does not match signature from certificate")
	ErrMarshallingCoseSignature         error = errors.New("Could not marshal COSE signature")
)

var (
	defaultRoot *x509.CertPool = createAWSNitroRoot()
)

func createAWSNitroRoot() *x509.CertPool {
	pool := x509.NewCertPool()

	ok := pool.AppendCertsFromPEM(AWSNitroEnclavesCertPEM)
	if !ok {
		return nil
	}

	return pool
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
func Verify(data []byte, options VerifyOptions) (*Result, error) {
	cose := CosePayload{}

	err := cbor.Unmarshal(data, &cose)
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

	if !options.AllowSelfSignedCert && nil == doc.CABundle {
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

	if !options.AllowSelfSignedCert && len(doc.CABundle) < 1 {
		return nil, ErrBadCABundle
	}

	if !options.AllowSelfSignedCert {
		for _, item := range doc.CABundle {
			if nil == item || len(item) < 1 || len(item) > 1024 {
				return nil, ErrBadCABundleItem
			}
		}
	}

	if nil != doc.PublicKey && len(doc.PublicKey) > maxPublicKeyLen {
		return nil, ErrBadPublicKey
	}
	if nil != doc.UserData && len(doc.UserData) > maxUserDataLen {
		return nil, ErrBadUserData
	}
	if nil != doc.Nonce && len(doc.Nonce) > maxNonceLen {
		return nil, ErrBadNonce
	}

	var certificates []*x509.Certificate
	if !options.AllowSelfSignedCert {
		certificates = make([]*x509.Certificate, 0, len(doc.CABundle)+1)
	} else {
		certificates = make([]*x509.Certificate, 1)
	}

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

	if !options.AllowSelfSignedCert {
		for _, item := range doc.CABundle {
			cert, err := x509.ParseCertificate(item)
			if nil != err {
				return nil, err
			}

			intermediates.AddCert(cert)
			certificates = append(certificates, cert)
		}
	}

	roots := options.Roots
	if nil == roots {
		roots = defaultRoot
	}
	if cert.IsCA {
		roots.AddCert(cert)
	}

	currentTime := options.CurrentTime
	if currentTime.IsZero() {
		currentTime = time.Now()
	}

	_, err = cert.Verify(
		x509.VerifyOptions{
			Intermediates: intermediates,
			Roots:         roots,
			CurrentTime:   currentTime,
			KeyUsages: []x509.ExtKeyUsage{
				x509.ExtKeyUsageAny,
			},
		},
	)
	if err != nil {
		return nil, err
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

	if !signatureOk && nil == err {
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

func NewDocumentFromCosePayloadBytes(bytes []byte) (*Document, error) {
	cose := CosePayload{}
	err := cbor.Unmarshal(bytes, &cose)
	if nil != err {
		return nil, fmt.Errorf("unmarshaling CosePayload: %w", err)
	}

	doc := Document{}
	err = cbor.Unmarshal(cose.Payload, &doc)
	if nil != err {
		return nil, fmt.Errorf("unmarshaling Document: %w", err)
	}
	return &doc, nil
}

func (d *Document) CreatedAt() time.Time {
	if d.Timestamp == 0 {
		return time.Time{}
	}

	// Pg. 64 of https://docs.aws.amazon.com/pdfs/enclaves/latest/user/enclaves-user.pdf
	// describes Timestamp as "UTC time when document was created, in milliseconds"
	return time.UnixMilli(int64(d.Timestamp))
}
