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
	"github.com/blocky/nitrite/mocks"
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

	attestatations := map[string]struct {
		attestation  []byte
		time         time.Time
		certProvider nitrite.CertProvider
	}{
		"nitro": {
			attestation:  nitroAttestation,
			time:         nitroAttestationTime,
			certProvider: nitrite.NewEmbeddedNitroCertProvider(),
		},
		"debug": {
			attestation:  debugNitroAttestation,
			time:         debugNitroAttestationTime,
			certProvider: nitrite.NewEmbeddedNitroCertProvider(),
		},
		"self-signed": {
			attestation:  selfSignedAttestation,
			time:         selfSignedAttestationTime,
			certProvider: nitrite.NewSelfSignedCertProvider(),
		},
	}

	for key := range attestatations {
		t.Run("happy path", func(t *testing.T) {
			t.Log(key)

			// when
			result, err := nitrite.Verify(
				attestatations[key].attestation,
				attestatations[key].certProvider,
				nitrite.WithAttestationTime(),
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
			_, err := nitrite.Verify(
				attestatations[key].attestation,
				certProvider,
				nitrite.WithAttestationTime(),
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
			_, err := nitrite.Verify(
				attestatations[key].attestation,
				certProvider,
				nitrite.WithAttestationTime(),
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
			_, err := nitrite.Verify(
				attestatations[key].attestation,
				certProvider,
				nitrite.WithAttestationTime(),
			)

			// then
			assert.ErrorContains(t, err, "verifying certificate")
		})

		timeOutOfBoundsTests := []struct {
			name        string
			timeOpt     nitrite.VerificationTimeFunc
			errContains string
		}{
			{
				"certificate expired",
				nitrite.WithTime(time.Date(10000, 0, 0, 0, 0, 0, 0, time.UTC)),
				"verifying certificate",
			},
			{
				"certificate not yet valid",
				nitrite.WithTime(time.Date(1970, 0, 0, 0, 0, 0, 0, time.UTC)),
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
				t.Log(key)

				// when
				_, err = nitrite.Verify(
					attestatations[key].attestation,
					attestatations[key].certProvider,
					tt.timeOpt,
				)

				// then
				assert.ErrorContains(t, err, tt.errContains)
			})
		}
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
			uint64(nitroAttestationTime.UnixMilli()),
			nitroAttestationTime,
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
