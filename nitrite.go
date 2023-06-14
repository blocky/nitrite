// Package nitrite implements attestation verification for AWS Nitro Enclaves.
package nitrite

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

type NitriteError string

func (n NitriteError) Error() string { return string(n) }

const (
	ErrBadCOSESign1Structure          = NitriteError("Data is not a COSESign1 array")
	ErrCOSESign1EmptyProtectedSection = NitriteError("COSESign1 protected section is nil or empty")
	ErrCOSESign1EmptyPayloadSection   = NitriteError("COSESign1 payload section is nil or empty")
	ErrCOSESign1EmptySignatureSection = NitriteError("COSESign1 signature section is nil or empty")
	ErrCOSESign1BadAlgorithm          = NitriteError("COSESign1 algorithm not ECDSA384")

	ErrBadAttestationDocument           = NitriteError("Bad attestation document")
	ErrMandatoryFieldsMissing           = NitriteError("One or more of mandatory fields missing")
	ErrBadDigest                        = NitriteError("Payload 'digest' is not SHA384")
	ErrBadTimestamp                     = NitriteError("Payload 'timestamp' is 0 or less")
	ErrBadPCRs                          = NitriteError("Payload 'pcrs' is less than 1 or more than 32")
	ErrBadPCRIndex                      = NitriteError("Payload 'pcrs' key index is not in [0, 32)")
	ErrBadPCRValue                      = NitriteError("Payload 'pcrs' value is nil or not of length {32,48,64}")
	ErrBadCABundle                      = NitriteError("Payload 'cabundle' has 0 elements")
	ErrBadCABundleItem                  = NitriteError("Payload 'cabundle' has a nil item or of length not in [1, 1024]")
	ErrBadPublicKey                     = NitriteError("Payload 'public_key' length greater than maxPublicKeyLen")
	ErrBadUserData                      = NitriteError("Payload 'user_data' length greater than maxUserDataLen")
	ErrBadNonce                         = NitriteError("Payload 'nonce' length greater than maxNonceLen")
	ErrBadCertificatePublicKeyAlgorithm = NitriteError("Payload 'certificate' has a bad public key algorithm (not ECDSA)")
	ErrBadCertificateSigningAlgorithm   = NitriteError("Payload 'certificate' has a bad public key signing algorithm (not ECDSAWithSHA384)")
	ErrBadSignature                     = NitriteError("Payload's signature does not match signature from certificate")
	ErrMarshallingCoseSignature         = NitriteError("Could not marshal COSE signature")
)

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

const (
	// DefaultCARoots contains the PEM encoded roots for verifying Nitro
	// Enclave attestation signatures. You can download them from
	// https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
	// It's recommended you calculate the SHA256 sum of this string and match
	// it to the one supplied in the AWS documentation
	// https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
	DefaultCARoots string = "-----BEGIN CERTIFICATE-----\nMIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL\nMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD\nVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4\nMTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL\nDANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG\nBSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb\n48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE\nh8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF\nR+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC\nMQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW\nrfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N\nIwLz3/Y=\n-----END CERTIFICATE-----\n"
)

var (
	defaultRoot *x509.CertPool = createAWSNitroRoot()
)

func createAWSNitroRoot() *x509.CertPool {
	pool := x509.NewCertPool()

	ok := pool.AppendCertsFromPEM([]byte(DefaultCARoots))
	if !ok {
		return nil
	}

	return pool
}

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
	cose, err := ExtractCosePayload(data)
	if err != nil {
		return nil, err
	}
	err = VerifyCosePayload(cose)
	if err != nil {
		return nil, err
	}

	header, err := ExtractCoseHeader(cose)
	if err != nil {
		return nil, err
	}
	err = VerifyCoseHeader(header)
	if err != nil {
		return nil, err
	}

	doc, err := ExtractAttestationDoc(cose)
	if err != nil {
		return nil, err
	}
	err = VerifyAttestationDoc(doc, options)
	if err != nil {
		return nil, err
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

func ExtractCosePayload(
	data []byte,
) (CosePayload, error) {
	cose := CosePayload{}
	err := cbor.Unmarshal(data, &cose)
	if nil != err {
		return CosePayload{}, ErrBadCOSESign1Structure
	}
	return cose, nil
}

func VerifyCosePayload(
	cose CosePayload,
) error {
	if cose.Protected == nil || len(cose.Protected) == 0 {
		return ErrCOSESign1EmptyProtectedSection
	}

	if cose.Payload == nil || len(cose.Payload) == 0 {
		return ErrCOSESign1EmptyPayloadSection
	}

	if cose.Signature == nil || len(cose.Signature) == 0 {
		return ErrCOSESign1EmptySignatureSection
	}
	return nil
}

func ExtractCoseHeader(
	cose CosePayload,
) (CoseHeader, error) {
	header := CoseHeader{}
	err := cbor.Unmarshal(cose.Protected, &header)
	if nil != err {
		return CoseHeader{}, ErrBadCOSESign1Structure
	}
	return header, nil
}

func VerifyCoseHeader(
	header CoseHeader,
) error {
	// https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
	switch header.Alg.(type) {
	case int64:
		switch header.Alg.(int64) {
		case -35: // Number for ES384 - OK
			return nil
		default:
			return ErrCOSESign1BadAlgorithm
		}
	case string:
		switch header.Alg.(string) {
		case "ES384": // OK
			return nil
		default:
			return ErrCOSESign1BadAlgorithm
		}
	default:
		return ErrCOSESign1BadAlgorithm
	}
}

func ExtractAttestationDoc(
	cose CosePayload,
) (Document, error) {
	doc := Document{}
	err := cbor.Unmarshal(cose.Payload, &doc)
	if nil != err {
		return Document{}, ErrBadAttestationDocument
	}
	return doc, nil
}

func VerifyAttestationDoc(
	doc Document,
	options VerifyOptions,
) error {
	if doc.ModuleID == "" ||
		doc.PCRs == nil ||
		doc.Certificate == nil {
		return ErrMandatoryFieldsMissing
	}

	if doc.Digest != "SHA384" {
		return ErrBadDigest
	}

	if doc.Timestamp < 1 {
		return ErrBadTimestamp
	}

	if len(doc.PCRs) < 1 || len(doc.PCRs) > 32 {
		return ErrBadPCRs
	}

	for i, pcr := range doc.PCRs {
		if i > 31 {
			return ErrBadPCRIndex
		}

		if pcr == nil {
			return ErrBadPCRValue
		}

		pcrLen := len(pcr)
		if !(pcrLen == 32 || pcrLen == 48 || pcrLen == 64) {
			return ErrBadPCRValue
		}
	}

	if doc.PublicKey != nil && len(doc.PublicKey) > maxPublicKeyLen {
		return ErrBadPublicKey
	}
	if doc.UserData != nil && len(doc.UserData) > maxUserDataLen {
		return ErrBadUserData
	}
	if doc.Nonce != nil && len(doc.Nonce) > maxNonceLen {
		return ErrBadNonce
	}

	if !options.AllowSelfSignedCert {
		if doc.CABundle == nil {
			return ErrMandatoryFieldsMissing
		}
		if len(doc.CABundle) < 1 {
			return ErrBadCABundle
		}
		for _, item := range doc.CABundle {
			if item == nil || len(item) < 1 || len(item) > 1024 {
				return ErrBadCABundleItem
			}
		}
	}
	return nil
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
