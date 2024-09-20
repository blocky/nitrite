package internal_test

import (
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/blocky/nitrite/internal"
	"github.com/blocky/nitrite/mocks"
)

// The canonical way to regenerate attestations is to request an attestation
// using hf/nsm/Send() and write the resulting bytes to a file as a base64
// string.

func TestNitrite_Verify(t *testing.T) {
	nitroAttestation, err := base64.StdEncoding.DecodeString(
		internal.NitroAttestationB64,
	)
	require.NoError(t, err)
	debugNitroAttestation, err := base64.StdEncoding.DecodeString(
		internal.DebugNitroAttestationB64,
	)
	require.NoError(t, err)
	selfSignedAttestation, err := base64.StdEncoding.DecodeString(
		internal.SelfSignedAttestationB64,
	)
	require.NoError(t, err)

	attestatations := map[string]struct {
		attestation  []byte
		time         time.Time
		certProvider internal.CertProvider
		allowDebug   bool
	}{
		"nitro": {
			attestation: nitroAttestation,
			time:        internal.NitroAttestationTime,
			certProvider: internal.NewNitroCertProvider(
				internal.NewEmbeddedRootCertZipReader(),
			),
		},
		"debug": {
			attestation: debugNitroAttestation,
			time:        internal.DebugNitroAttestationTime,
			certProvider: internal.NewNitroCertProvider(
				internal.NewEmbeddedRootCertZipReader(),
			),
			allowDebug: true,
		},
		"self-signed": {
			attestation:  selfSignedAttestation,
			time:         internal.SelfSignedAttestationTime,
			certProvider: internal.NewSelfSignedCertProvider(),
		},
	}

	for key := range attestatations {
		t.Run("happy path", func(t *testing.T) {
			t.Log(key)

			// when
			result, err := internal.Verify(
				attestatations[key].attestation,
				attestatations[key].certProvider,
				internal.WithAttestationTime(),
				attestatations[key].allowDebug,
			)

			// then
			require.NoError(t, err)
			// make sure at least one of the fields is populated and attested
			assert.Equal(
				t,
				attestatations[key].time.UTC(),
				result.Document.CreatedAt().UTC(),
			)
		})

		t.Run("cannot get root certificates", func(t *testing.T) {
			t.Log(key)

			// given
			certProvider := mocks.NewNitriteCertProvider(t)

			// expecting
			certProvider.EXPECT().Roots().Return(nil, assert.AnError)

			// when
			_, err := internal.Verify(
				attestatations[key].attestation,
				certProvider,
				internal.WithAttestationTime(),
				attestatations[key].allowDebug,
			)

			// then
			assert.ErrorIs(t, err, assert.AnError)
			assert.ErrorContains(t, err, "getting root certificates")
		})

		t.Run("unknown signing authority - nil roots", func(t *testing.T) {
			t.Log(key)

			// given
			certProvider := mocks.NewNitriteCertProvider(t)

			// expecting
			certProvider.EXPECT().Roots().Return(nil, nil)

			// when
			_, err := internal.Verify(
				attestatations[key].attestation,
				certProvider,
				internal.WithAttestationTime(),
				attestatations[key].allowDebug,
			)

			// then
			assert.ErrorContains(t, err, "verifying certificate")
		})

		t.Run("unknown signing authority - empty roots", func(t *testing.T) {
			t.Log(key)

			// given
			certProvider := mocks.NewNitriteCertProvider(t)

			// expecting
			certProvider.EXPECT().Roots().Return(x509.NewCertPool(), nil)

			// when
			_, err := internal.Verify(
				attestatations[key].attestation,
				certProvider,
				internal.WithAttestationTime(),
				attestatations[key].allowDebug,
			)

			// then
			assert.ErrorContains(t, err, "verifying certificate")
		})

		timeOutOfBoundsTests := []struct {
			name        string
			timeOpt     internal.VerificationTimeFunc
			errContains string
		}{
			{
				"certificate expired",
				internal.WithTime(time.Date(10000, 0, 0, 0, 0, 0, 0, time.UTC)),
				"verifying certificate",
			},
			{
				"certificate not yet valid",
				internal.WithTime(time.Date(1970, 0, 0, 0, 0, 0, 0, time.UTC)),
				"verifying certificate",
			},
			{
				"zero time",
				internal.WithTime(time.Time{}),
				"verification time is 0",
			},
		}
		for _, tt := range timeOutOfBoundsTests {
			t.Run(tt.name, func(t *testing.T) {
				t.Log(key)

				// when
				_, err = internal.Verify(
					attestatations[key].attestation,
					attestatations[key].certProvider,
					tt.timeOpt,
					attestatations[key].allowDebug,
				)

				// then
				assert.ErrorContains(t, err, tt.errContains)
			})
		}
	}

	t.Run("attestation was generated in debug mode", func(t *testing.T) {
		// when
		_, err := internal.Verify(
			attestatations["debug"].attestation,
			attestatations["debug"].certProvider,
			internal.WithAttestationTime(),
			false,
		)

		// then
		assert.ErrorContains(t, err, "attestation was generated in debug mode")
	})
}
