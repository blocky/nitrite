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
	*Result,
	error,
) {
	coseSign1, err := MakeCoseSign1FromBytes(attestation)
	if err != nil {
		return nil, fmt.Errorf("making CoseSign1 from attestation bytes: %w", err)
	}

	doc, err := MakeDocumentFromBytes(coseSign1.Payload)
	if nil != err {
		return nil, fmt.Errorf("making document from payload: %w", err)
	}

	docDebug, err := doc.Debug()
	if err != nil {
		return nil, fmt.Errorf("getting document debug: %w", err)
	}

	if !allowDebug && docDebug {
		return nil, fmt.Errorf("attestation was generated in debug mode")
	}

	certificates, err := doc.CheckCertificates(certProvider, verificationTime)
	if err != nil {
		return nil, fmt.Errorf("checking document certificates: %w", err)

	}
	if len(certificates) < 1 {
		return nil, fmt.Errorf("certificates chain is empty")
	}

	sigStruct, err := coseSign1.CheckSignature(certificates[0].PublicKey.(*ecdsa.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("checking CoseSign1 signature: %w", err)
	}

	return &Result{
		Document:     &doc,
		Certificates: certificates,
		Protected:    coseSign1.Protected,
		Unprotected:  coseSign1.Unprotected,
		Payload:      coseSign1.Payload,
		Signature:    coseSign1.Signature,
		COSESign1:    sigStruct,
	}, err
}
