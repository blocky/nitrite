package nitrite_test

import (
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/blocky/nitrite"
)

// The canonical way to regenerate attestations is to request an attestation
// using hf/nsm/Send() and write the resulting bytes to a file as a base64
// string.

//go:embed testdata/nitro_attestation.b64
var attestationB64 string
var attestationTime = time.Date(2024, time.September, 7, 14, 37, 39, 545000000, time.UTC)

//go:embed testdata/nitro_attestation_debug.b64
var debugAttestationB64 string

func TestNitrite_Verify(t *testing.T) {
	regularAttestation, err := base64.StdEncoding.DecodeString(attestationB64)
	require.NoError(t, err)
	debugAttestation, err := base64.StdEncoding.DecodeString(debugAttestationB64)
	require.NoError(t, err)

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(nitrite.AWSNitroEnclavesCertPEM)
	require.True(t, ok)

	happyPathTests := []struct {
		name        string
		attestation []byte
	}{
		{
			"regular attestation",
			regularAttestation,
		},
		{
			"debug attestation",
			debugAttestation,
		},
	}
	for _, tt := range happyPathTests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			result, err := nitrite.Verify(
				tt.attestation,
				nitrite.WithRootCert(roots),
				nitrite.WithAttestationTime(),
			)

			// then
			require.NoError(t, err)
			require.NotEmpty(t, result)
		})
	}

	unknownSigningAuthorityTests := []struct {
		name        string
		rootCertOpt nitrite.RootCertFunc
	}{
		{
			"nil roots",
			nitrite.WithRootCert(nil),
		},
		{
			"empty roots",
			nitrite.WithRootCert(x509.NewCertPool()),
		},
	}
	for _, tt := range unknownSigningAuthorityTests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			_, err := nitrite.Verify(
				regularAttestation,
				tt.rootCertOpt,
				nitrite.WithAttestationTime(),
			)

			// then
			assert.ErrorContains(t, err, "verifying certificate")
		})
	}

	timeOutOfBoundsTests := []struct {
		name        string
		timeOpt     nitrite.VerificationTimeFunc
		errContains string
	}{
		{
			"certificate expired",
			nitrite.WithTime(attestationTime.Add(-time.Hour)),
			"verifying certificate",
		},
		{
			"certificate not yet valid",
			nitrite.WithTime(attestationTime.Add(time.Hour * 8760)),
			"verifying certificate",
		},
		{
			"zero time",
			nitrite.WithTime(time.Time{}),
			"verification time is 0",
		},
	}
	for _, tt := range timeOutOfBoundsTests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			_, err := nitrite.Verify(
				regularAttestation,
				nitrite.WithDefaultRootCert(),
				tt.timeOpt,
			)

			// then
			assert.ErrorContains(t, err, tt.errContains)
		})
	}
}

func TestDocument_CreatedAt(t *testing.T) {
	happyPathTests := []struct {
		name      string
		timestamp uint64
		wantTime  time.Time
	}{
		{
			"happy path",
			uint64(attestationTime.UnixMilli()),
			attestationTime,
		},
		{
			"zero time",
			uint64(0),
			time.Time{},
		},
	}
	for _, tt := range happyPathTests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			doc := nitrite.Document{Timestamp: tt.timestamp}

			// when
			gotTime := doc.CreatedAt()

			// then
			assert.Equal(t, tt.wantTime.UTC(), gotTime.UTC())
		})
	}
}
