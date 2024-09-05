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

//go:embed testdata/nitro_attestation.txt
var nitroAttestString string

func TestNitrite_Verify(t *testing.T) {
	attestBytes, err := base64.StdEncoding.DecodeString(nitroAttestString)
	require.NoError(t, err)
	attestTime, err := nitrite.Timestamp(attestBytes)
	require.NoError(t, err)

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(nitrite.AWSNitroEnclavesCertPEM)
	require.True(t, ok)

	t.Run("happy path", func(t *testing.T) {
		// when
		result, err := nitrite.Verify(
			attestBytes,
			nitrite.WithDefaultRootCert(),
			nitrite.WithAttestationTime(),
		)

		// then
		require.NoError(t, err)
		require.NotEmpty(t, result)
	})

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
			_, err = nitrite.Verify(
				attestBytes,
				tt.rootCertOpt,
				nitrite.WithAttestationTime(),
			)

			// then
			assert.ErrorContains(t, err, "verifying certificate")
		})
	}

	timeOutOfBoundsTests := []struct {
		name    string
		timeOpt nitrite.VerificationTimeFunc
	}{
		{
			"certificate expired",
			nitrite.WithTime(attestTime.Add(-time.Hour)),
		},
		{
			"certificate not yet valid",
			nitrite.WithTime(attestTime.Add(time.Hour * 8760)),
		},
		{
			"zero time",
			nitrite.WithTime(time.Time{}),
		},
	}
	for _, tt := range timeOutOfBoundsTests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			_, err := nitrite.Verify(
				attestBytes,
				nitrite.WithDefaultRootCert(),
				tt.timeOpt,
			)

			// then
			assert.ErrorContains(t, err, "certificate has expired or is not yet valid")
		})
	}
}
