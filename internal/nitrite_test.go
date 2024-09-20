package internal_test

import (
	_ "embed"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/blocky/nitrite/internal"
)

// The canonical way to regenerate attestations is to request an attestation
// using hf/nsm/Send() and write the resulting bytes to a file as a base64
// string.

//go:embed testdata/nitro_attestation.b64
var nitroAttestationB64 string
var nitroAttestationTime = time.Date(2024, time.September, 7, 14, 37, 39, 545000000, time.UTC)

//go:embed testdata/nitro_attestation_debug.b64
var debugNitroAttestationB64 string
var debugNitroAttestationTime = time.Date(2024, time.September, 7, 14, 38, 6, 508000000, time.UTC)

//go:embed testdata/selfsigned_attestation.b64
var selfSignedAttestationB64 string
var selfSignedAttestationTime = time.Date(2024, time.April, 17, 18, 51, 46, 0, time.UTC)

func TestNitrite_Verify(t *testing.T) {
	nitroAttestation, err := base64.StdEncoding.DecodeString(nitroAttestationB64)
	require.NoError(t, err)
	debugNitroAttestation, err := base64.StdEncoding.DecodeString(debugNitroAttestationB64)
	require.NoError(t, err)
	selfSignedAttestation, err := base64.StdEncoding.DecodeString(selfSignedAttestationB64)
	require.NoError(t, err)

	tests := []struct {
		name         string
		attestation  []byte
		time         time.Time
		certProvider internal.CertProvider
	}{
		{
			name:        "happy path - nitro",
			attestation: nitroAttestation,
			time:        nitroAttestationTime,
			certProvider: internal.NewNitroCertProvider(
				internal.NewEmbeddedRootCertZipReader(),
			),
		},
		{
			name:        "happy path - debug nitro",
			attestation: debugNitroAttestation,
			time:        debugNitroAttestationTime,
			certProvider: internal.NewNitroCertProvider(
				internal.NewEmbeddedRootCertZipReader(),
			),
		},
		{
			name:         "happy path - self signed",
			attestation:  selfSignedAttestation,
			time:         selfSignedAttestationTime,
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
}
