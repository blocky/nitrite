// Package nitrite implements attestation verification for AWS Nitro Enclaves.
package internal

import (
	"crypto/ecdsa"
	_ "embed"
	"fmt"
	"time"
)

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

type VerificationTimeFunc func(Document) time.Time

func WithAttestationTime() VerificationTimeFunc {
	return func(doc Document) time.Time {
		return doc.CreatedAt()
	}
}

func WithTime(t time.Time) VerificationTimeFunc {
	return func(_ Document) time.Time {
		return t
	}
}

// The process for verifying Nitro attestations is documented here:
// https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/4b851f3006c6fa98f23dcffb2cba03b39de9b8af/docs/attestation_process.md
//
// Revocation checks are NOT performed and you should check for revoked
// certificates by looking at the `Certificates` field in the `Result`.
func Verify(
	attestation []byte,
	certProvider CertProvider,
	verificationTime VerificationTimeFunc,
	allowDebug bool,
) (
	Document,
	error,
) {
	coseSign1 := CoseSign1{}
	err := coseSign1.UnmarshalBinary(attestation)
	if err != nil {
		return Document{}, fmt.Errorf("unmarshaling CoseSign1 from attestation bytes: %w", err)
	}

	doc := Document{}
	err = doc.UnmarshalBinary(coseSign1.Payload)
	if nil != err {
		return Document{}, fmt.Errorf("unmarshaling document from payload: %w", err)
	}

	docDebug, err := doc.Debug()
	if err != nil {
		return Document{}, fmt.Errorf("getting document debug: %w", err)
	}

	if !allowDebug && docDebug {
		return Document{}, fmt.Errorf("attestation was generated in debug mode")
	}

	certificates, err := doc.Verify(certProvider, verificationTime)
	if err != nil {
		return Document{}, fmt.Errorf("verifying document: %w", err)

	}
	if len(certificates) < 1 {
		return Document{}, fmt.Errorf("certificates chain is empty")
	}

	err = coseSign1.Verify(certificates[0].PublicKey.(*ecdsa.PublicKey))
	if err != nil {
		return Document{}, fmt.Errorf("verifying CoseSign1: %w", err)
	}
	return doc, err
}
