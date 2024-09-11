package internal

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
)

// asserts/aws_nitro_enclaves.crt contains the PEM encoded roots for verifying Nitro
//	Enclave attestation signatures. You can download them from
//	https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
//	It's recommended you calculate the SHA256 sum of this string and match
//	it to the one supplied in the AWS documentation
//	https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html

//go:embed assets/aws_nitro_enclaves.crt
var nitroCertPEM []byte

//go:embed assets/selfsigned_cert.der
var selfSignedCertDER []byte

type NitroCertProvider struct{}

func MakeNitroCertProvider() NitroCertProvider {
	return NitroCertProvider{}
}

func (cp NitroCertProvider) Roots() (*x509.CertPool, error) {
	certs := x509.NewCertPool()
	ok := certs.AppendCertsFromPEM(nitroCertPEM)
	if !ok {
		return nil, fmt.Errorf("appending cert")
	}
	return certs, nil
}

type SelfSignedCertProvider struct{}

func MakeSelfSignedCertProvider() SelfSignedCertProvider {
	return SelfSignedCertProvider{}
}

func (cp SelfSignedCertProvider) Roots() (*x509.CertPool, error) {
	certs := x509.NewCertPool()
	pemCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: selfSignedCertDER,
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

// todo: test these
