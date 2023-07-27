package cose_test

import (
	"crypto/ecdsa"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/blocky/nitrite/pkg/attestation"
	"github.com/blocky/nitrite/pkg/cose"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed test/nitro-stag-attestation.txt
var nitroStagAttestBase64 string

//go:embed test/nitro-stag-attestation-doc.json
var nitroStagAttestDocJSON string

func makeAttestationDocFromJSON(
	attestationDocJSON []byte,
) (attestation.Document, error) {
	doc := attestation.Document{}
	err := json.Unmarshal(attestationDocJSON, &doc)
	if err != nil {
		return attestation.Document{}, err
	}
	return doc, nil
}

func TestCose_ExtractCosePayload(t *testing.T) {
	attestBytes, err := base64.StdEncoding.DecodeString(nitroStagAttestBase64)
	require.NoError(t, err)

	t.Run("happy path", func(t *testing.T) {
		cosePayload, err := cose.ExtractCosePayload(attestBytes)
		assert.NoError(t, err)
		assert.NotNil(t, cosePayload.Protected)
		assert.NotNil(t, cosePayload.Payload)
		assert.NotNil(t, cosePayload.Signature)
		assert.Greater(t, len(cosePayload.Protected), 0)
		assert.Greater(t, len(cosePayload.Payload), 0)
		assert.Greater(t, len(cosePayload.Signature), 0)
	})

	t.Run("unmarshal error", func(t *testing.T) {
		cosePayload, err := cose.ExtractCosePayload([]byte("invalid"))
		assert.Error(t, err)
		assert.Empty(t, cosePayload)
	})
}

func TestCose_VerifyCosePayload(t *testing.T) {
	attestBytes, err := base64.StdEncoding.DecodeString(nitroStagAttestBase64)
	require.NoError(t, err)

	t.Run("happy path", func(t *testing.T) {
		cosePayload, err := cose.ExtractCosePayload(attestBytes)
		require.NoError(t, err)

		err = cose.VerifyCosePayload(cosePayload)
		assert.NoError(t, err)
	})

	t.Run("ErrCOSESign1EmptyProtectedSection nil", func(t *testing.T) {
		cosePayload, err := cose.ExtractCosePayload(attestBytes)
		require.NoError(t, err)

		cosePayload.Protected = nil
		err = cose.VerifyCosePayload(cosePayload)
		assert.ErrorContains(t, err, cose.ErrCOSESign1EmptyProtectedSection)
	})

	t.Run("ErrCOSESign1EmptyProtectedSection length zero", func(t *testing.T) {
		cosePayload, err := cose.ExtractCosePayload(attestBytes)
		require.NoError(t, err)

		cosePayload.Protected = make([]byte, 0)
		err = cose.VerifyCosePayload(cosePayload)
		assert.ErrorContains(t, err, cose.ErrCOSESign1EmptyProtectedSection)
	})

	t.Run("ErrCOSESign1EmptyPayloadSection nil", func(t *testing.T) {
		cosePayload, err := cose.ExtractCosePayload(attestBytes)
		require.NoError(t, err)

		cosePayload.Payload = nil
		err = cose.VerifyCosePayload(cosePayload)
		assert.ErrorContains(t, err, cose.ErrCOSESign1EmptyPayloadSection)
	})

	t.Run("ErrCOSESign1EmptyPayloadSection length zero", func(t *testing.T) {
		cosePayload, err := cose.ExtractCosePayload(attestBytes)
		require.NoError(t, err)

		cosePayload.Payload = make([]byte, 0)
		err = cose.VerifyCosePayload(cosePayload)
		assert.ErrorContains(t, err, cose.ErrCOSESign1EmptyPayloadSection)
	})

	t.Run("ErrCOSESign1EmptySignatureSection nil", func(t *testing.T) {
		cosePayload, err := cose.ExtractCosePayload(attestBytes)
		require.NoError(t, err)

		cosePayload.Signature = nil
		err = cose.VerifyCosePayload(cosePayload)
		assert.ErrorContains(t, err, cose.ErrCOSESign1EmptySignatureSection)
	})

	t.Run("ErrCOSESign1EmptySignatureSection length zero", func(t *testing.T) {
		cosePayload, err := cose.ExtractCosePayload(attestBytes)
		require.NoError(t, err)

		cosePayload.Signature = make([]byte, 0)
		err = cose.VerifyCosePayload(cosePayload)
		assert.ErrorContains(t, err, cose.ErrCOSESign1EmptySignatureSection)
	})
}

func TestCose_ExtractCoseHeader(t *testing.T) {
	attestBytes, err := base64.StdEncoding.DecodeString(nitroStagAttestBase64)
	require.NoError(t, err)

	cosePayload, err := cose.ExtractCosePayload(attestBytes)
	require.NoError(t, err)

	t.Run("happy path", func(t *testing.T) {
		coseHeader, err := cose.ExtractCoseHeader(cosePayload)
		assert.NoError(t, err)
		assert.NotNil(t, coseHeader.Alg)
	})

	t.Run("unmarshal error", func(t *testing.T) {
		coseHeader, err := cose.ExtractCoseHeader(cose.CosePayload{})
		assert.Error(t, err)
		assert.Empty(t, coseHeader)
	})
}

func TestCose_VerifyCoseHeader(t *testing.T) {
	attestBytes, err := base64.StdEncoding.DecodeString(nitroStagAttestBase64)
	require.NoError(t, err)

	cosePayload, err := cose.ExtractCosePayload(attestBytes)
	require.NoError(t, err)

	t.Run("happy path", func(t *testing.T) {
		coseHeader, err := cose.ExtractCoseHeader(cosePayload)
		require.NoError(t, err)

		err = cose.VerifyCoseHeader(coseHeader)
		assert.NoError(t, err)
	})

	t.Run("ErrCOSESign1BadAlgorithm int", func(t *testing.T) {
		badInt := 0
		coseHeader := cose.CoseHeader{}
		coseHeader.Alg = &badInt

		err = cose.VerifyCoseHeader(coseHeader)
		assert.ErrorContains(t, err, cose.ErrCOSESign1BadAlgorithm)

	})

	t.Run("ErrCOSESign1BadAlgorithm string", func(t *testing.T) {
		badString := "Bad String"
		coseHeader := cose.CoseHeader{}
		coseHeader.Alg = &badString

		err = cose.VerifyCoseHeader(coseHeader)
		assert.ErrorContains(t, err, cose.ErrCOSESign1BadAlgorithm)
	})
}

func TestCose_VerifyCoseSign1(t *testing.T) {
	attestBytes, err := base64.StdEncoding.DecodeString(nitroStagAttestBase64)
	require.NoError(t, err)

	cosePayload, err := cose.ExtractCosePayload(attestBytes)
	require.NoError(t, err)

	doc, err := makeAttestationDocFromJSON(
		[]byte(nitroStagAttestDocJSON),
	)
	require.NoError(t, err)

	allowSelfSignedCert := false
	cert, _, intermediates, err := attestation.ExtractCertificates(
		doc,
		allowSelfSignedCert,
	)
	require.NoError(t, err)

	validTime := time.Date(2023, time.July, 10, 15, 22, 53, 0, time.UTC)
	err = attestation.VerifyCertificates(
		cert,
		intermediates,
		nil,
		validTime,
	)
	require.NoError(t, err)

	t.Run("happy path", func(t *testing.T) {
		sign1, err := cose.VerifyCoseSign1(cosePayload, cert)
		assert.NoError(t, err)
		assert.NotNil(t, sign1)
	})

	t.Run("ErrBadSignature", func(t *testing.T) {
		cosePayload.Signature = nil
		sign1, err := cose.VerifyCoseSign1(cosePayload, cert)
		assert.ErrorContains(t, err, cose.ErrBadSignature)
		assert.Nil(t, sign1)
	})
}

func TestCose_CheckECDSASignature(t *testing.T) {
	attestBytes, err := base64.StdEncoding.DecodeString(nitroStagAttestBase64)
	require.NoError(t, err)

	cosePayload, err := cose.ExtractCosePayload(attestBytes)
	require.NoError(t, err)

	doc, err := makeAttestationDocFromJSON(
		[]byte(nitroStagAttestDocJSON),
	)
	require.NoError(t, err)

	allowSelfSignedCert := false
	cert, _, intermediates, err := attestation.ExtractCertificates(
		doc,
		allowSelfSignedCert,
	)
	require.NoError(t, err)

	validTime := time.Date(2023, time.July, 10, 15, 22, 53, 0, time.UTC)
	err = attestation.VerifyCertificates(
		cert,
		intermediates,
		nil,
		validTime,
	)
	require.NoError(t, err)

	coseSig := cose.CoseSignature{
		Context:     "Signature1",
		Protected:   cosePayload.Protected,
		ExternalAAD: []byte{},
		Payload:     cosePayload.Payload,
	}
	sigStruct, err := cbor.Marshal(&coseSig)
	require.NoError(t, err)

	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok)

	t.Run("happy path", func(t *testing.T) {
		ok := cose.CheckECDSASignatureRaw(
			publicKey,
			sigStruct,
			cosePayload.Signature,
			publicKey.Curve.Params().Name,
		)
		assert.True(t, ok)
	})

	t.Run("bad curve name", func(t *testing.T) {
		ok := cose.CheckECDSASignatureRaw(
			publicKey,
			sigStruct,
			cosePayload.Signature,
			"bad curve name",
		)
		assert.False(t, ok)
	})

	t.Run("bad sigstruct", func(t *testing.T) {
		ok := cose.CheckECDSASignatureRaw(
			publicKey,
			sigStruct[1:],
			cosePayload.Signature,
			publicKey.Curve.Params().Name,
		)
		assert.False(t, ok)
	})

	t.Run("bad signature", func(t *testing.T) {
		ok := cose.CheckECDSASignatureRaw(
			publicKey,
			sigStruct,
			cosePayload.Signature[1:],
			publicKey.Curve.Params().Name,
		)
		assert.False(t, ok)
	})
}

func TestCose_ExtractAttestationDoc(t *testing.T) {
	attestBytes, err := base64.StdEncoding.DecodeString(nitroStagAttestBase64)
	require.NoError(t, err)

	cosePayload, err := cose.ExtractCosePayload(attestBytes)
	require.NoError(t, err)

	t.Run("happy path", func(t *testing.T) {
		doc, err := cose.ExtractAttestationDoc(cosePayload)
		assert.NoError(t, err)
		assert.NotNil(t, doc.PCRs)
		assert.NotNil(t, doc.Certificate)
		assert.NotNil(t, doc.CABundle)
		assert.NotNil(t, doc.PublicKey)
		assert.NotNil(t, doc.UserData)
		assert.NotNil(t, doc.Nonce)
	})

	t.Run("unmarshal error", func(t *testing.T) {
		cosePayload.Payload = []byte("bad payload")
		doc, err := cose.ExtractAttestationDoc(cosePayload)
		assert.ErrorContains(t, err, cose.ErrBadAttestationDocument)
		assert.Empty(t, doc)
	})
}
