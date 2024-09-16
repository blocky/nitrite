package nitrite

import (
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"

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

type VerifierConfig struct {
}

func (v *VerifierConfig) WithBob() *VerifierConfig {
}

func NewVerifier(
	certProviderOpt func() (CertProvider, error),
	verificationOpt ...func() (*Verifier, error), // timestamp, debug, ...
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
// would be nice if the options pattern not contradicted itself
// - maybe we have two enumerated options for now and attestation time, but then
//   we could have an internal function for testing that allows for specific time.Time

func WithAttestationTime() (, error) {
	optionsStruct.VerificationTimeFunc =  func(doc internal.Document) time.Time {

		return doc.CreatedAt()
	}, nil
}

func WithTime(t time.Time) (VerificationTimeFunc, error) {
	return func(_ internal.Document) time.Time {
		return t
	}, nil
}

// default no debug
func WithDebug() (*VerifierConfig, error) {
}

func NewDefaultVerifier() (*Verifier, error) {
	return NewVerifier(
		WithNitroCertProvider,
		WithAttestationTime,
	)
}

func (v *Verifier) Verify(attestation []byte) (*Result, error) {
	cose := cosePayload{}

	err := cbor.Unmarshal(attestation, &cose)


	doc := Document{}

	err = cbor.Unmarshal(cose.Payload, &doc)

	document.Verify()

	verificationTime := docuemnt.CreatedAt()

	err = cose.Verify(verificationTime time.time)


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
