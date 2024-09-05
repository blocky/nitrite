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
var nitroAttestTime = time.Date(2024, time.May, 7, 17, 43, 6, 613000000, time.UTC)

func TestTimestamp(t *testing.T) {
	attestBytes, err := base64.StdEncoding.DecodeString(nitroAttestString)
	require.NoError(t, err)

	t.Run("happy path", func(t *testing.T) {
		// given
		wantTime := nitroAttestTime

		// when
		gotTime, err := nitrite.Timestamp(attestBytes)

		// then
		require.NoError(t, err)
		assert.Equal(t, wantTime, gotTime.UTC())
	})
}

func TestNitrite_Verify(t *testing.T) {
	attestBytes, err := base64.StdEncoding.DecodeString(nitroAttestString)
	require.NoError(t, err)

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(nitrite.AWSNitroEnclavesCertPEM)
	require.True(t, ok)

	t.Run("happy path", func(t *testing.T) {
		// given
		timestamp, err := nitrite.Timestamp(attestBytes)
		require.NoError(t, err)

		opts := nitrite.VerifyOptions{
			CurrentTime: timestamp,
			Roots:       roots,
		}

		// when
		result, err := nitrite.Verify(attestBytes, opts)

		// then
		require.NoError(t, err)
		require.NotEmpty(t, result)
	})

	timeOutOfBoundsTests := []struct {
		name string
		time time.Time
	}{
		{"certificate expired", nitroAttestTime.Add(-time.Hour)},
		{"certificate not yet valid", nitroAttestTime.Add(time.Hour * 8760)},
		{"zero time", time.Time{}},
	}
	for _, tt := range timeOutOfBoundsTests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			opts := nitrite.VerifyOptions{
				CurrentTime: tt.time,
				Roots:       roots,
			}

			// when
			_, err := nitrite.Verify(attestBytes, opts)

			// then
			assert.ErrorContains(t, err, "certificate has expired or is not yet valid")
		})
	}

	unknownSigningAuthorityTests := []struct {
		name  string
		roots *x509.CertPool
	}{
		// {"nil roots", nil}, // todo: handle this case
		{"empty roots", x509.NewCertPool()},
	}
	for _, tt := range unknownSigningAuthorityTests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			timestamp, err := nitrite.Timestamp(attestBytes)
			require.NoError(t, err)

			opts := nitrite.VerifyOptions{
				CurrentTime: timestamp,
				Roots:       tt.roots,
			}

			// when
			_, err = nitrite.Verify(attestBytes, opts)

			// then
			assert.ErrorContains(t, err, "verifying certificate")
		})
	}
}
