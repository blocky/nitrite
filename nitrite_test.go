package nitrite_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/blocky/nitrite"
	"github.com/blocky/nitrite/internal"
)

func TestNewVerifier(t *testing.T) {
	happyPathTests := []struct {
		name string
		opts []nitrite.VerifierConfigOption
	}{
		{
			name: "happy path - no options",
			opts: nil,
		},
		{
			name: "happy path - embedded nitro cert provider",
			opts: []nitrite.VerifierConfigOption{
				nitrite.WithCertProvider(nitrite.EmbeddedNitroCertProvider),
			},
		},
		{
			name: "happy path - self signed cert provider",
			opts: []nitrite.VerifierConfigOption{
				nitrite.WithCertProvider(nitrite.SelfSignedCertProvider),
			},
		},
		{
			name: "happy path - attestation time",
			opts: []nitrite.VerifierConfigOption{
				nitrite.WithVerificationTime(nitrite.AttestationTime),
			},
		},
		{
			name: "happy path - current time",
			opts: []nitrite.VerifierConfigOption{
				nitrite.WithVerificationTime(nitrite.CurrentTime),
			},
		},
		{
			name: "happy path - allow debug",
			opts: []nitrite.VerifierConfigOption{
				nitrite.WithAllowDebug(true),
			},
		},
		{
			name: "happy path - no debug",
			opts: []nitrite.VerifierConfigOption{
				nitrite.WithAllowDebug(false),
			},
		},
		{
			name: "happy path - all options",
			opts: []nitrite.VerifierConfigOption{
				nitrite.WithCertProvider(nitrite.EmbeddedNitroCertProvider),
				nitrite.WithVerificationTime(nitrite.AttestationTime),
				nitrite.WithAllowDebug(true),
			},
		},
		{
			name: "happy path - overwriting options",
			opts: []nitrite.VerifierConfigOption{
				nitrite.WithCertProvider(nitrite.EmbeddedNitroCertProvider),
				nitrite.WithCertProvider(nitrite.SelfSignedCertProvider),
				nitrite.WithVerificationTime(nitrite.AttestationTime),
				nitrite.WithVerificationTime(nitrite.CurrentTime),
				nitrite.WithAllowDebug(true),
				nitrite.WithAllowDebug(false),
			},
		},
	}
	for _, tt := range happyPathTests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			gotVerifier, err := nitrite.NewVerifier(tt.opts...)

			// then
			require.NoError(t, err)
			require.NotEmpty(t, gotVerifier)
		})
	}
}

func TestVerifier_Verify(t *testing.T) {
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

	happyPathTests := []struct {
		name        string
		opts        []nitrite.VerifierConfigOption
		attestation []byte
	}{
		{
			name: "happy path - embedded nitro cert provider",
			opts: []nitrite.VerifierConfigOption{
				nitrite.WithCertProvider(nitrite.EmbeddedNitroCertProvider),
				nitrite.WithVerificationTime(nitrite.AttestationTime),
				nitrite.WithAllowDebug(false),
			},
			attestation: nitroAttestation,
		},
		{
			name: "happy path - embedded nitro cert provider with debug",
			opts: []nitrite.VerifierConfigOption{
				nitrite.WithCertProvider(nitrite.EmbeddedNitroCertProvider),
				nitrite.WithVerificationTime(nitrite.AttestationTime),
				nitrite.WithAllowDebug(true),
			},
			attestation: debugNitroAttestation,
		},
		{
			name: "happy path - self signed cert provider",
			opts: []nitrite.VerifierConfigOption{
				nitrite.WithCertProvider(nitrite.SelfSignedCertProvider),
				nitrite.WithVerificationTime(nitrite.AttestationTime),
				nitrite.WithAllowDebug(false),
			},
			attestation: selfSignedAttestation,
		},
	}
	for _, tt := range happyPathTests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			verifier, err := nitrite.NewVerifier(tt.opts...)
			require.NoError(t, err)

			// when
			_, err = verifier.Verify(tt.attestation)

			// then
			require.NoError(t, err)
		})
	}

	t.Run("happy path - debug not allowed", func(t *testing.T) {
		// given
		verifier, err := nitrite.NewVerifier(
			nitrite.WithCertProvider(nitrite.EmbeddedNitroCertProvider),
			nitrite.WithVerificationTime(nitrite.AttestationTime),
			nitrite.WithAllowDebug(false),
		)
		require.NoError(t, err)

		// when
		_, err = verifier.Verify(debugNitroAttestation)

		// then
		assert.ErrorContains(
			t,
			err,
			"verifying attestation: attestation was generated in debug mode",
		)
	})

	t.Run("cannot verify attestation", func(t *testing.T) {
		// given
		verifier, err := nitrite.NewVerifier(
			nitrite.WithCertProvider(nitrite.EmbeddedNitroCertProvider),
			nitrite.WithVerificationTime(nitrite.AttestationTime),
			nitrite.WithAllowDebug(false),
		)
		require.NoError(t, err)

		// when
		_, err = verifier.Verify([]byte("invalid attestation"))

		// then
		assert.ErrorContains(t, err, "verifying attestation")
	})
}
