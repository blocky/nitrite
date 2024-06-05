package nitrite_test

import (
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"testing"
	"time"

	"github.com/blocky/nitrite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/nitro_attestation.txt
var nitroAttestString string

func TestNitrite_Verify(t *testing.T) {
	attestBytes, err := base64.StdEncoding.DecodeString(nitroAttestString)
	require.NoError(t, err)

	doc := nitrite.Document{}
	err = doc.FromCosePayloadBytes(attestBytes)
	require.NoError(t, err)

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(nitrite.AWSNitroEnclavesCertPEM)
	require.True(t, ok)

	t.Run("happy path", func(t *testing.T) {
		opts := nitrite.VerifyOptions{
			CurrentTime: doc.CreatedAt(),
			Roots:       roots,
		}

		result, err := nitrite.Verify(attestBytes, opts)
		require.NoError(t, err)
		assert.Equal(t, *result.Document, doc)
		assert.True(t, result.SignatureOK)
	})

	t.Run("expired attestation", func(t *testing.T) {
		opts := nitrite.VerifyOptions{
			CurrentTime: time.Now(),
			Roots:       roots,
		}

		result, err := nitrite.Verify(attestBytes, opts)
		assert.ErrorContains(t, err, "certificate has expired or is not yet valid")
		assert.Nil(t, result)
	})
}

func TestNitriteDocument_FromCosePayloadBytes(t *testing.T) {
	attestBytes, err := base64.StdEncoding.DecodeString(nitroAttestString)
	require.NoError(t, err)

	t.Run("happy path", func(t *testing.T) {
		doc := nitrite.Document{}
		err = doc.FromCosePayloadBytes(attestBytes)
		require.NoError(t, err)

		assert.Equal(t, doc.ModuleID, "i-0eec57d9c38705a57-enc018f25eda1b897b7")
		assert.Equal(t, doc.Timestamp, uint64(1715103786613))
		assert.Equal(t, doc.Digest, "SHA384")
		assert.Empty(t, doc.UserData)
		assert.Empty(t, doc.Nonce)
	})

	t.Run("error unmarshaling CosePayload", func(t *testing.T) {
		doc := nitrite.Document{}
		err = doc.FromCosePayloadBytes([]byte{})
		assert.ErrorContains(t, err, "unmarshaling CosePayload")
	})
}
