package internal_test

import (
	_ "embed"
	"encoding/base64"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/blocky/nitrite/internal"
)

// The canonical way to regenerate attestations is to request an attestation
// using hf/nsm/Send() and write the resulting bytes to a file as a base64
// string.

func TestNitrite_Verify(t *testing.T) {
	// TODO: Place into initAttestations to share with other tests?
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

	tests := []struct {
		name         string
		attestation  []byte
		time         time.Time
		certProvider internal.CertProvider
		allowDebug   bool
	}{
		{
			name:        "happy path - nitro",
			attestation: nitroAttestation,
			time:        internal.NitroAttestationTime,
			certProvider: internal.NewNitroCertProvider(
				internal.NewEmbeddedRootCertZipReader(),
			),
		},
		{
			name:        "happy path - debug nitro",
			attestation: debugNitroAttestation,
			time:        internal.DebugNitroAttestationTime,
			certProvider: internal.NewNitroCertProvider(
				internal.NewEmbeddedRootCertZipReader(),
			),
			allowDebug: true,
		},
		{
			name:         "happy path - self signed",
			attestation:  selfSignedAttestation,
			time:         internal.SelfSignedAttestationTime,
			certProvider: internal.NewSelfSignedCertProvider(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// when
			result, err := internal.Verify(
				tt.attestation,
				tt.certProvider,
				internal.WithAttestationTime(),
				tt.allowDebug,
			)

			// then
			require.NoError(t, err)
			// make sure at least one of the fields is populated and attested
			assert.Equal(
				t,
				tt.time.UTC(),
				result.Document.CreatedAt().UTC(),
			)
		})

	}

	t.Run("invalid CoseSign1", func(t *testing.T) {
		// given
		badAttestation := []byte("invalid CoseSign1 structure")

		// when
		_, err = internal.Verify(
			badAttestation,
			internal.NewNitroCertProvider(
				internal.NewEmbeddedRootCertZipReader(),
			),
			internal.WithAttestationTime(),
			false,
		)

		// then
		assert.ErrorContains(t, err, "unmarshaling CoseSign1 from attestation bytes")
	})

	t.Run("invalid document", func(t *testing.T) {
		// given
		nitroCoseSign1 := internal.CoseSign1{}
		err := nitroCoseSign1.UnmarshalBinary(nitroAttestation)
		require.NoError(t, err)
		require.NoError(t, err)

		nitroCoseSign1.Payload = []byte("not a valid document")
		badNitroAttestation, err := cbor.Marshal(nitroCoseSign1)
		require.NoError(t, err)

		// when
		_, err = internal.Verify(
			badNitroAttestation,
			internal.NewNitroCertProvider(
				internal.NewEmbeddedRootCertZipReader(),
			),
			internal.WithAttestationTime(),
			false,
		)

		// then
		assert.ErrorContains(t, err, "making document from payload")
	})

	t.Run("debug mode not allowed", func(t *testing.T) {
		// when
		_, err := internal.Verify(
			debugNitroAttestation,
			internal.NewNitroCertProvider(
				internal.NewEmbeddedRootCertZipReader(),
			),
			internal.WithAttestationTime(),
			false,
		)

		// then
		assert.ErrorContains(t, err, "attestation was generated in debug mode")
	})

	t.Run("invalid document certificate chain", func(t *testing.T) {
		// when
		_, err = internal.Verify(
			nitroAttestation,
			internal.NewSelfSignedCertProvider(),
			internal.WithAttestationTime(),
			false,
		)

		// then
		assert.ErrorContains(t, err, "checking document certificates")
	})

	t.Run("invalid CoseSign1 signature", func(t *testing.T) {
		// given
		nitroCoseSign1 := internal.CoseSign1{}
		err := nitroCoseSign1.UnmarshalBinary(nitroAttestation)
		require.NoError(t, err)

		nitroCoseSign1.Signature = []byte("not a valid signature")
		badNitroAttestation, err := cbor.Marshal(nitroCoseSign1)
		require.NoError(t, err)

		// when
		_, err = internal.Verify(
			badNitroAttestation,
			internal.NewNitroCertProvider(
				internal.NewEmbeddedRootCertZipReader(),
			),
			internal.WithAttestationTime(),
			false,
		)

		// then
		assert.ErrorContains(t, err, "verifying CoseSign1 signature")
	})
}
