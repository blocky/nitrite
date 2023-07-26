package nitrite_test

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/blocky/nitrite/pkg/attestation"
	"github.com/blocky/nitrite/pkg/nitrite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed test/nitro-stag-attestation.txt
var nitroStagAttestBase64 string

//go:embed test/nitro-stag-attestation-doc.json
var nitroStagAttestDocJSON string

func makeAttestationDocFromJSON(
	attestationDocJSON []byte,
) (*attestation.Document, error) {
	doc := attestation.Document{}
	err := json.Unmarshal(attestationDocJSON, &doc)
	if err != nil {
		return nil, err
	}
	if doc.UserData == nil {
		doc.UserData = make([]byte, 0)
	}
	if doc.Nonce == nil {
		doc.Nonce = make([]byte, 0)
	}
	return &doc, nil
}

func makeNitroStagVerifyOptions(
	currentTime time.Time,
) nitrite.VerifyOptions {
	return nitrite.VerifyOptions{
		Roots:               nil,
		CurrentTime:         currentTime,
		AllowSelfSignedCert: false,
	}
}

func TestNitrite_Verify(t *testing.T) {
	attestBytes, err := base64.StdEncoding.DecodeString(nitroStagAttestBase64)
	require.NoError(t, err)

	t.Run("happy path", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		validTime := time.Date(2023, time.July, 10, 15, 22, 53, 0, time.UTC)
		verifyOptions := makeNitroStagVerifyOptions(validTime)

		res, err := nitrite.Verify(attestBytes, verifyOptions)
		assert.NoError(t, err)
		assert.Equal(t, doc, res.Document)
	})

	t.Run("invalid time", func(t *testing.T) {
		invalidTime := time.Date(2022, time.July, 10, 15, 22, 53, 0, time.UTC)
		verifyOptions := makeNitroStagVerifyOptions(invalidTime)

		res, err := nitrite.Verify(attestBytes, verifyOptions)
		assert.ErrorContains(t, err, "is not yet valid")
		assert.Nil(t, res)
	})

	t.Run("expired time", func(t *testing.T) {
		expiredTime := time.Date(2024, time.July, 10, 15, 22, 53, 0, time.UTC)
		verifyOptions := makeNitroStagVerifyOptions(expiredTime)

		res, err := nitrite.Verify(attestBytes, verifyOptions)
		assert.ErrorContains(t, err, "certificate has expired")
		assert.Nil(t, res)
	})

	t.Run("nitro self-signed mismatch", func(t *testing.T) {
		validTime := time.Date(2023, time.July, 10, 15, 22, 53, 0, time.UTC)
		verifyOptions := makeNitroStagVerifyOptions(validTime)
		verifyOptions.AllowSelfSignedCert = true

		res, err := nitrite.Verify(attestBytes, verifyOptions)
		assert.ErrorContains(t, err, "certificate signed by unknown authority")
		assert.Nil(t, res)
	})
}

func FuzzNitrite_Verify(f *testing.F) {
	attestBytes, err := base64.StdEncoding.DecodeString(nitroStagAttestBase64)
	require.NoError(f, err)

	badBytes := attestBytes[:len(attestBytes)-1]

	tests := []struct {
		data []byte
	}{
		{data: badBytes},
	}
	for _, test := range tests {
		f.Add(test.data)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		validTime := time.Date(2023, time.July, 10, 15, 22, 53, 0, time.UTC)
		verifyOptions := makeNitroStagVerifyOptions(validTime)

		res, err := nitrite.Verify(data, verifyOptions)
		assert.Error(t, err)
		assert.Nil(t, res)
	})
}
