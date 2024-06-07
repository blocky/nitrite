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

//go:embed testdata/expired_nitro_attestation.txt
var expiredNitroAttestString string

func TestNitrite_Verify(t *testing.T) {
	expiredAttestBytes, err := base64.StdEncoding.DecodeString(expiredNitroAttestString)
	require.NoError(t, err)

	doc, err := nitrite.NewDocumentFromCosePayloadBytes(expiredAttestBytes)
	require.NoError(t, err)

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(nitrite.AWSNitroEnclavesCertPEM)
	require.True(t, ok)

	t.Run("happy path", func(t *testing.T) {
		opts := nitrite.VerifyOptions{
			CurrentTime: doc.CreatedAt(),
			Roots:       roots,
		}

		result, err := nitrite.Verify(expiredAttestBytes, opts)
		require.NoError(t, err)
		assert.Equal(t, *result.Document, *doc)
		assert.True(t, result.SignatureOK)
	})

	t.Run("expired attestation", func(t *testing.T) {
		opts := nitrite.VerifyOptions{
			CurrentTime: time.Now(),
			Roots:       roots,
		}

		result, err := nitrite.Verify(expiredAttestBytes, opts)
		assert.ErrorContains(t, err, "certificate has expired or is not yet valid")
		assert.Nil(t, result)
	})
}

func TestNitriteDocument_NewDocumentFromCosePayloadBytes(t *testing.T) {
	expiredAttestBytes, err := base64.StdEncoding.DecodeString(expiredNitroAttestString)
	require.NoError(t, err)

	t.Run("happy path", func(t *testing.T) {
		doc, err := nitrite.NewDocumentFromCosePayloadBytes(expiredAttestBytes)
		require.NoError(t, err)

		assert.Equal(t, doc.ModuleID, "i-0eec57d9c38705a57-enc018f25eda1b897b7")
		assert.Equal(t, doc.Timestamp, uint64(1715103786613))
		assert.Equal(t, doc.Digest, "SHA384")
		assert.Empty(t, doc.UserData)
		assert.Empty(t, doc.Nonce)
	})

	t.Run("error unmarshaling CosePayload", func(t *testing.T) {
		_, err = nitrite.NewDocumentFromCosePayloadBytes([]byte{})
		assert.ErrorContains(t, err, "unmarshaling CosePayload")
	})
}

func TestNitriteDocument_CreatedAt(t *testing.T) {
	t.Run("empty document", func(t *testing.T) {
		doc := &nitrite.Document{}
		createdAt := doc.CreatedAt()
		assert.Equal(t, createdAt, time.Time{})
	})
}
