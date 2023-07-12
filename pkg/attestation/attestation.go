package attestation

import (
	"crypto/x509"
	"time"

	"github.com/blocky/nitrite/pkg/nitrite_error"
)

// Size of these fields (in bytes) comes from AWS Nitro documentation at
// https://docs.aws.amazon.com/enclaves/latest/user/enclaves-user.pdf
// from May 4, 2022.
// With MaxNonceLen = 1024, MaxUserDataLen = 1024, and MaxPublicKeyLen = 1024
// the total AttestationLen = 6591.
// An experiment on August 8, 2022, allowed user data to be maximized to
// MaxUserDataLen = 3868 with MaxNonceLen = 40 and MaxPublicKeyLen = 1024 for
// the total AttestationLen = 8451.
const (
	MaxNonceLen       = 1024
	MaxUserDataLen    = 2048
	MaxPublicKeyLen   = 1024
	MaxAttestationLen = 6591
)

// Document represents the AWS Nitro Enclave Attestation Document.
type Document struct {
	ModuleID    string          `cbor:"module_id" json:"module_id"`
	Timestamp   uint64          `cbor:"timestamp" json:"timestamp"`
	Digest      string          `cbor:"digest" json:"digest"`
	PCRs        map[uint][]byte `cbor:"pcrs" json:"pcrs"`
	Certificate []byte          `cbor:"certificate" json:"certificate"`
	CABundle    [][]byte        `cbor:"cabundle" json:"cabundle"`
	PublicKey   []byte          `cbor:"public_key" json:"public_key,omitempty"`
	UserData    []byte          `cbor:"user_data" json:"user_data,omitempty"`
	Nonce       []byte          `cbor:"nonce" json:"nonce,omitempty"`
}

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

func VerifyAttestationDoc(
	doc Document,
	allowSelfSignedCert bool,
) error {
	if doc.ModuleID == "" ||
		doc.PCRs == nil ||
		doc.Certificate == nil {
		return nitrite_error.ErrMandatoryFieldsMissing
	}
	if doc.Digest != "SHA384" {
		return nitrite_error.ErrBadDigest
	}
	if doc.Timestamp < 1 {
		return nitrite_error.ErrBadTimestamp
	}
	if len(doc.PCRs) < 1 || len(doc.PCRs) > 32 {
		return nitrite_error.ErrBadPCRs
	}

	for _, pcr := range doc.PCRs {
		if pcr == nil {
			return nitrite_error.ErrBadPCRValue
		}
		pcrLen := len(pcr)
		if !(pcrLen == 32 || pcrLen == 48 || pcrLen == 64 || pcrLen == 96) {
			return nitrite_error.ErrBadPCRValue
		}
	}

	if doc.PublicKey != nil && len(doc.PublicKey) > MaxPublicKeyLen {
		return nitrite_error.ErrBadPublicKey
	}
	if doc.UserData != nil && len(doc.UserData) > MaxUserDataLen {
		return nitrite_error.ErrBadUserData
	}
	if doc.Nonce != nil && len(doc.Nonce) > MaxNonceLen {
		return nitrite_error.ErrBadNonce
	}

	if !allowSelfSignedCert {
		if doc.CABundle == nil {
			return nitrite_error.ErrMandatoryFieldsMissing
		}
		if len(doc.CABundle) < 1 {
			return nitrite_error.ErrBadCABundle
		}
		for _, item := range doc.CABundle {
			if item == nil || len(item) < 1 || len(item) > 1024 {
				return nitrite_error.ErrBadCABundleItem
			}
		}
	}
	return nil
}

func ExtractCertificates(
	doc Document,
	allowSelfSignedCert bool,
) (*x509.Certificate, []*x509.Certificate, *x509.CertPool, error) {
	cert, err := x509.ParseCertificate(doc.Certificate)
	if err != nil {
		return nil, nil, nil, err
	}

	if cert.PublicKeyAlgorithm != x509.ECDSA {
		return nil, nil, nil, nitrite_error.ErrBadCertificatePublicKeyAlgorithm
	}
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		return nil, nil, nil, nitrite_error.ErrBadCertificateSigningAlgorithm
	}

	var certificates []*x509.Certificate
	if !allowSelfSignedCert {
		certificates = make([]*x509.Certificate, 0, len(doc.CABundle)+1)
	} else {
		certificates = make([]*x509.Certificate, 1)
	}
	certificates = append(certificates, cert)

	intermediates := x509.NewCertPool()
	if !allowSelfSignedCert {
		for _, item := range doc.CABundle {
			cert1, err := x509.ParseCertificate(item)
			if err != nil {
				return nil, nil, nil, err
			}
			intermediates.AddCert(cert1)
			certificates = append(certificates, cert1)
		}
	}
	return cert, certificates, intermediates, nil
}

func VerifyCertificates(
	cert *x509.Certificate,
	intermediates *x509.CertPool,
	roots *x509.CertPool,
	currentTime time.Time,
) error {
	if roots == nil {
		roots = defaultRoot
	}
	if cert.IsCA {
		roots.AddCert(cert)
	}

	if currentTime.IsZero() {
		currentTime = time.Now()
	}

	_, err := cert.Verify(
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
		return err
	}
	return nil
}
