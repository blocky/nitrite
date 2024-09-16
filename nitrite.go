package nitrite

import (
	"fmt"
	"time"

	"github.com/blocky/nitrite/internal"
)

type Document = internal.Document
type Result = internal.Result

type CertProvider int

const (
	EmbeddedNitroCertProvider CertProvider = iota
	FetchingNitroCertProvider
	SelfSignedCertProvider
)

type VerificationTime int

const (
	AttestationTime VerificationTime = iota
	CurrentTime
)

type VerifierConfig struct {
	certProvider     CertProvider
	verificationTime VerificationTime
	debug            bool
}

type VerifierConfigOption func(*VerifierConfig)

func WithCertProvider(p CertProvider) VerifierConfigOption {
	return func(c *VerifierConfig) {
		c.certProvider = p
	}
}

func WithVerificationTime(t VerificationTime) VerifierConfigOption {
	return func(c *VerifierConfig) {
		c.verificationTime = t
	}
}

func WithDebug() VerifierConfigOption {
	return func(c *VerifierConfig) {
		c.debug = true
	}
}

type Verifier struct {
	certProvider     internal.CertProvider
	verificationTime internal.VerificationTimeFunc
	debug            bool
}

func NewVerifier(options ...VerifierConfigOption) (*Verifier, error) {
	config := &VerifierConfig{
		certProvider:     EmbeddedNitroCertProvider,
		verificationTime: AttestationTime,
		debug:            false,
	}
	for _, opt := range options {
		opt(config)
	}

	return NewVerifierFromConfig(config)
}

func NewVerifierFromConfig(config *VerifierConfig) (*Verifier, error) {
	var verifier = new(Verifier)

	switch config.certProvider {
	case EmbeddedNitroCertProvider:
		verifier.certProvider = internal.NewNitroCertProvider(
			internal.NewEmbeddedRootCertZipReader(),
		)
	case FetchingNitroCertProvider:
		reader, err := internal.NewFetchingRootCertZipReader()
		if nil != err {
			return nil,
				fmt.Errorf("creating fetching root cert zip reader: %w", err)
		}
		verifier.certProvider = internal.NewNitroCertProvider(reader)
	case SelfSignedCertProvider:
		verifier.certProvider = internal.NewSelfSignedCertProvider()
	default:
		return nil,
			fmt.Errorf("unknown cert provider: %d", config.certProvider)
	}

	switch config.verificationTime {
	case AttestationTime:
		verifier.verificationTime = func(doc internal.Document) time.Time {
			return doc.CreatedAt()
		}
	case CurrentTime:
		verifier.verificationTime = func(_ internal.Document) time.Time {
			return time.Now()
		}
	default:
		return nil,
			fmt.Errorf("unknown verification time: %d", config.verificationTime)
	}

	verifier.debug = config.debug

	return verifier, nil
}

func (v *Verifier) Verify(attestation []byte) (*Result, error) {
	// todo: handle the debug flag
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
