package internal

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// AWS_NitroEnclaves_Root-G1.zip file and its digest are advertised on
//	https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html

const AWSNitroEnclavesRootURL = "https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip"

//go:embed assets/AWS_NitroEnclaves_Root-G1.zip
var AWSNitroEnclavesRootZip []byte

//go:embed assets/AWS_NitroEnclaves_Root-G1.sha256.hex
var AWSNitroEnclavesRootSHA256Hex string

type CertProvider interface {
	Roots() (*x509.CertPool, error)
}

type UnzipAWSRootCertsFunc func(zipBytes []byte) (pemBytes []byte, err error)

func UnzipAWSRootCerts(zipBytes []byte) ([]byte, error) {
	zipReader, err := zip.NewReader(
		bytes.NewReader(zipBytes),
		int64(len(zipBytes)),
	)
	if err != nil {
		return nil, fmt.Errorf("creating zip reader: %w", err)
	}

	if len(zipReader.File) != 1 {
		return nil, fmt.Errorf("unexpected file count: %d", len(zipReader.File))
	}
	if zipReader.File[0].Name != "root.pem" {
		return nil, fmt.Errorf("unexpected file name: %s", zipReader.File[0].Name)
	}

	pemFile, err := zipReader.File[0].Open()
	if err != nil {
		return nil, fmt.Errorf("opening zip file: %w", err)
	}

	pemBytes, err := io.ReadAll(pemFile)
	if err != nil {
		return nil, fmt.Errorf("reading pem file: %w", err)
	}

	return pemBytes, nil
}

func NewEmbeddedRootCertZipReader() io.ReadCloser {
	return io.NopCloser(bytes.NewReader(AWSNitroEnclavesRootZip))
}

func NewFetchingRootCertZipReader() (io.ReadCloser, error) {
	return NewFetchingRootCertZipReaderWithClient(http.DefaultClient)
}

func NewFetchingRootCertZipReaderWithClient(
	client *http.Client,
) (
	io.ReadCloser,
	error,
) {
	resp, err := client.Get(AWSNitroEnclavesRootURL)
	if err != nil {
		return nil, fmt.Errorf("fetching root file: %w", err)
	}

	return resp.Body, nil
}

type NitroCertProvider struct {
	rootCerts         *x509.CertPool
	rootCertZipReader io.ReadCloser
	UnzipAWSRootCerts UnzipAWSRootCertsFunc
}

func NewNitroCertProvider(rootCertZipReader io.ReadCloser) *NitroCertProvider {
	return &NitroCertProvider{
		rootCerts:         nil,
		rootCertZipReader: rootCertZipReader,
		UnzipAWSRootCerts: UnzipAWSRootCerts,
	}
}

func (cp *NitroCertProvider) Roots() (*x509.CertPool, error) {
	if nil != cp.rootCerts {
		return cp.rootCerts, nil
	}

	zipBytes, err := io.ReadAll(cp.rootCertZipReader)
	defer cp.rootCertZipReader.Close()
	if err != nil {
		return nil, fmt.Errorf("reading ZIP bytes: %w", err)
	}

	digest := sha256.Sum256(zipBytes)
	digestHex := hex.EncodeToString(digest[:])
	if digestHex != strings.TrimSpace(AWSNitroEnclavesRootSHA256Hex) {
		return nil, fmt.Errorf(
			"digest mismatch: expected %s, got %s",
			AWSNitroEnclavesRootSHA256Hex,
			digestHex,
		)
	}

	rootCertsPEM, err := cp.UnzipAWSRootCerts(zipBytes)
	if err != nil {
		return nil, fmt.Errorf("unzipping roots: %w", err)
	}

	certs := x509.NewCertPool()
	ok := certs.AppendCertsFromPEM(rootCertsPEM)
	if !ok {
		return nil, fmt.Errorf("appending cert")
	}

	cp.rootCerts = certs

	return cp.rootCerts, nil
}

// Deprecated: Remove selfSignedCertDER as part of https://blocky.atlassian.net/browse/BKY-5620
//
//go:embed assets/selfsigned_cert.der
var selfSignedCertDER []byte

// Deprecated: Remove SelfSignedCertProvider as part of https://blocky.atlassian.net/browse/BKY-5620
type SelfSignedCertProvider struct {
}

// Deprecated: Remove NewSelfSignedCertProvider as part of https://blocky.atlassian.net/browse/BKY-5620
func NewSelfSignedCertProvider() *SelfSignedCertProvider {
	return &SelfSignedCertProvider{}
}

// Deprecated: Remove SelfSignedCertProvider.Roots as part of https://blocky.atlassian.net/browse/BKY-5620
func (cp *SelfSignedCertProvider) Roots() (*x509.CertPool, error) {
	return cp.RootWithCert(selfSignedCertDER)
}

// Deprecated: Remove SelfSignedCertProvider.RootWithCert as part of https://blocky.atlassian.net/browse/BKY-5620
func (_ *SelfSignedCertProvider) RootWithCert(
	derCert []byte,
) (
	*x509.CertPool,
	error,
) {
	certs := x509.NewCertPool()
	pemCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derCert,
	})
	if nil == pemCert {
		return nil, fmt.Errorf("encoding self-signed cert")
	}

	ok := certs.AppendCertsFromPEM(pemCert)
	if !ok {
		return nil, fmt.Errorf("appending cert")
	}

	return certs, nil
}
