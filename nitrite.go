package nitrite

import (
	"fmt"
	"time"

	"github.com/blocky/nitrite/internal"
)

type Document = internal.Document
type Result = internal.Result
type CertProvider = internal.CertProvider
type VerificationTimeFunc = internal.VerificationTimeFunc

type Verifier struct {
	certProvider     CertProvider
	verificationTime VerificationTimeFunc
}

func NewVerifier(
	certProviderOpt func() (CertProvider, error),
	verificationTimeOpt func() (VerificationTimeFunc, error),
) (*Verifier, error) {
	certProvider, err := certProviderOpt()
	if err != nil {
		return nil, fmt.Errorf("creating cert provider: %w", err)
	}

	verificationTimeFunc, err := verificationTimeOpt()
	if err != nil {
		return nil, fmt.Errorf("creating verification time func: %w", err)
	}

	return &Verifier{
		certProvider:     certProvider,
		verificationTime: verificationTimeFunc,
	}, nil
}

func WithNitroCertProvider() (CertProvider, error) {
	return internal.NewNitroCertProvider(
		internal.NewEmbeddedRootCertZipReader(),
	), nil
}

func WithFetchingNitroCertProvider() (CertProvider, error) {
	reader, err := internal.NewFetchingRootCertZipReader()
	if nil != err {
		return nil, fmt.Errorf("creating fetching root cert zip reader: %w", err)
	}

	return internal.NewNitroCertProvider(reader), nil
}

func WithAttestationTime() (VerificationTimeFunc, error) {
	return func(doc internal.Document) time.Time {
		return doc.CreatedAt()
	}, nil
}

func WithTime(t time.Time) (VerificationTimeFunc, error) {
	return func(_ internal.Document) time.Time {
		return t
	}, nil
}

func NewDefaultVerifier() (*Verifier, error) {
	return NewVerifier(
		WithNitroCertProvider,
		WithAttestationTime,
	)
}

func (v *Verifier) Verify(attestation []byte) (*Result, error) {
	result, err := internal.Verify(
		attestation,
		v.certProvider,
		v.verificationTime,
	)
	if err != nil {
		return nil, fmt.Errorf("verifying attestation: %w", err)
	}

	result.Document = (*Document)(result.Document)

	return result, nil
}
