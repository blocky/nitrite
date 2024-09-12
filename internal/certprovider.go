package internal

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"net/http"
)

// asserts/aws_nitro_enclaves.crt contains the PEM encoded roots for verifying Nitro
//	Enclave attestation signatures. You can download them from
//	https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
//	It's recommended you calculate the SHA256 sum of this string and match
//	it to the one supplied in the AWS documentation
//	https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html

const AWSNitroEnclavesRoot = "https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip"

//go:embed assets/aws_nitro_enclaves.crt
var NitroCertPEM []byte

//go:embed assets/selfsigned_cert.der
var selfSignedCertDER []byte

type NitroCertProvider struct {
	certs *x509.CertPool
}

func NewNitroCertProvider() *NitroCertProvider {
	return &NitroCertProvider{}
}

func (cp *NitroCertProvider) Roots() (*x509.CertPool, error) {
	if cp.certs == nil {
		certs, err := cp.RootsWithCerts(NitroCertPEM)
		if err != nil {
			return nil, err
		}
		cp.certs = certs
	}

	return cp.certs, nil
}

func (_ *NitroCertProvider) RootsWithCerts(
	pemCerts []byte,
) (
	*x509.CertPool,
	error,
) {
	certs := x509.NewCertPool()
	ok := certs.AppendCertsFromPEM(pemCerts)
	if !ok {
		return nil, fmt.Errorf("appending cert")
	}
	return certs, nil
}

// todo: add a thing to make sure we have the latest
// todo: decide what to do in main

type FetchingNitroCertProvider struct {
	roots *x509.CertPool
}

func NewFetchingNitroCertProvider() *NitroCertProvider {
	return &NitroCertProvider{}
}

func (cp FetchingNitroCertProvider) Roots() (*x509.CertPool, error) {
	if cp.roots == nil {

		resp, err := http.Get(AWSNitroEnclavesRoot)
		defer resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("fetching root file: %w", err)
		}
	}

	return cp.roots, nil
}

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
