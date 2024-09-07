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
	attestation, err := base64.StdEncoding.DecodeString(attestationB64)
	require.NoError(t, err)

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(nitrite.AWSNitroEnclavesCertPEM)
	require.True(t, ok)

	happyPathTests := []struct {
		name           string
		attestationB64 string
	}{
		{
			"regular attestation",
			attestationB64,
		},
		{
			"debug attestation",
			debugAttestationB64,
		},
	}
	for _, tt := range happyPathTests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			result, err := nitrite.Verify(
				attestation,
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
				attestation,
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
				attestation,
				nitrite.WithDefaultRootCert(),
				tt.timeOpt,
			)

			// then
			assert.ErrorContains(t, err, tt.errContains)
		})
	}
}

func TestDocument_CreatedAt(t *testing.T) {
	attestation, err := base64.StdEncoding.DecodeString(attestationB64)
	require.NoError(t, err)

	t.Run("happy path", func(t *testing.T) {
		// given
		wantTime := attestationTime

		result, err := nitrite.Verify(
			attestation,
			nitrite.WithDefaultRootCert(),
			nitrite.WithAttestationTime(),
		)

		// when
		gotTime := result.Document.CreatedAt()

		// then
		require.NoError(t, err)
		assert.Equal(t, wantTime.UTC(), gotTime.UTC())
	})
}
