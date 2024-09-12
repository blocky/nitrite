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

type UnzipRootsFunc func(zipBytes []byte) (pemBytes []byte, err error)

func UnzipRoots(zipBytes []byte) ([]byte, error) {
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

type NitroCertProvider struct {
	certs *x509.CertPool
}

func NewNitroCertProvider() *NitroCertProvider {
	return &NitroCertProvider{}
}

func (cp *NitroCertProvider) Roots() (*x509.CertPool, error) {
	if cp.certs == nil {
		certs, err := cp.RootsWithCerts(
			AWSNitroEnclavesRootZip,
			AWSNitroEnclavesRootSHA256Hex,
			UnzipRoots,
		)
		if err != nil {
			return nil, fmt.Errorf("creating certs: %w", err)
		}
		cp.certs = certs
	}

	return cp.certs, nil
}

func (_ *NitroCertProvider) RootsWithCerts(
	rootsZIPBytes []byte,
	rootsDigestHex string,
	unzipRoots UnzipRootsFunc,
) (
	*x509.CertPool,
	error,
) {
	digest := sha256.Sum256(rootsZIPBytes)
	digestHex := hex.EncodeToString(digest[:])
	if digestHex != strings.TrimSpace(rootsDigestHex) {
		return nil,
			fmt.Errorf("digest mismatch: %s != %s", digestHex, rootsDigestHex)
	}

	pemCerts, err := unzipRoots(rootsZIPBytes)
	if err != nil {
		return nil, fmt.Errorf("unzipping roots: %w", err)
	}

	certs := x509.NewCertPool()
	ok := certs.AppendCertsFromPEM(pemCerts)
	if !ok {
		return nil, fmt.Errorf("appending cert")
	}
	return certs, nil
}

type FetchingNitroCertProvider struct {
	httpClient *http.Client
	certs      *x509.CertPool
}

func NewFetchingNitroCertProvider() *FetchingNitroCertProvider {
	return NewFetchingNitroCertProviderWithClient(http.DefaultClient)
}

func NewFetchingNitroCertProviderWithClient(
	client *http.Client,
) *FetchingNitroCertProvider {
	return &FetchingNitroCertProvider{
		certs:      nil,
		httpClient: client,
	}
}

func (cp FetchingNitroCertProvider) Roots() (*x509.CertPool, error) {
	if cp.certs == nil {
		resp, err := cp.httpClient.Get(AWSNitroEnclavesRootURL)
		if err != nil {
			return nil, fmt.Errorf("fetching root file: %w", err)
		}
		defer resp.Body.Close()

		zipBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("reading ZIP bytes: %w", err)
		}

		certs, err := NewNitroCertProvider().RootsWithCerts(
			zipBytes,
			AWSNitroEnclavesRootSHA256Hex,
			UnzipRoots,
		)
		if err != nil {
			return nil, fmt.Errorf("creating certs: %w", err)
		}

		cp.certs = certs
	}

	return cp.certs, nil
}

// TODO: Remove SelfSignedCertProvider as part of
//  https://blocky.atlassian.net/browse/BKY-5620

//go:embed assets/selfsigned_cert.der
var selfSignedCertDER []byte

type SelfSignedCertProvider struct {
	certs *x509.CertPool
}

func NewSelfSignedCertProvider() *SelfSignedCertProvider {
	return &SelfSignedCertProvider{}
}

func (cp *SelfSignedCertProvider) Roots() (*x509.CertPool, error) {
	if cp.certs == nil {
		certs, err := cp.RootWithCert(selfSignedCertDER)
		if err != nil {
			return nil, err
		}
		cp.certs = certs
	}

	return cp.certs, nil
}

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
