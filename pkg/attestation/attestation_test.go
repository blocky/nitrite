package attestation_test

import (
	_ "embed"
	"encoding/json"
	"testing"
	"time"

	"github.com/blocky/nitrite/pkg/attestation"
	"github.com/blocky/nitrite/pkg/nitrite_error"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestAttestation_VerifyAttestationDoc(t *testing.T) {
	allowSelfSignedCert := false
	t.Run("happy path", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		err = attestation.VerifyAttestationDoc(doc, allowSelfSignedCert)
		assert.NoError(t, err)
	})

	t.Run("ErrMandatoryFieldsMissing ModuleID", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		doc.ModuleID = ""
		err = attestation.VerifyAttestationDoc(doc, allowSelfSignedCert)
		assert.ErrorIs(t, err, nitrite_error.ErrMandatoryFieldsMissing)
	})

	t.Run("ErrMandatoryFieldsMissing PCRs nil", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		doc.PCRs = nil
		err = attestation.VerifyAttestationDoc(doc, allowSelfSignedCert)
		assert.ErrorIs(t, err, nitrite_error.ErrMandatoryFieldsMissing)
	})

	t.Run("ErrMandatoryFieldsMissing Certificate nil", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		doc.Certificate = nil
		err = attestation.VerifyAttestationDoc(doc, allowSelfSignedCert)
		assert.ErrorIs(t, err, nitrite_error.ErrMandatoryFieldsMissing)
	})

	t.Run("ErrMandatoryFieldsMissing CABundle nil", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		doc.CABundle = nil
		err = attestation.VerifyAttestationDoc(doc, allowSelfSignedCert)
		assert.ErrorIs(t, err, nitrite_error.ErrMandatoryFieldsMissing)
	})

	t.Run("ErrBadDigest", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		doc.Digest = "SHA256"
		err = attestation.VerifyAttestationDoc(doc, allowSelfSignedCert)
		assert.ErrorIs(t, err, nitrite_error.ErrBadDigest)
	})

	t.Run("ErrBadTimestamp", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		doc.Timestamp = 0
		err = attestation.VerifyAttestationDoc(doc, allowSelfSignedCert)
		assert.ErrorIs(t, err, nitrite_error.ErrBadTimestamp)
	})

	t.Run("ErrBadPCRs < 0", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		doc.PCRs = make(map[uint][]byte)
		err = attestation.VerifyAttestationDoc(doc, allowSelfSignedCert)
		assert.ErrorIs(t, err, nitrite_error.ErrBadPCRs)
	})

	t.Run("ErrBadPCRs > 32", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		pcr := doc.PCRs[0]
		doc.PCRs = make(map[uint][]byte)
		for i := uint(0); i <= 32; i++ {
			doc.PCRs[i] = pcr
		}
		err = attestation.VerifyAttestationDoc(doc, allowSelfSignedCert)
		assert.ErrorIs(t, err, nitrite_error.ErrBadPCRs)
	})

	t.Run("ErrBadPCRValue nil", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		doc.PCRs[0] = nil
		err = attestation.VerifyAttestationDoc(doc, allowSelfSignedCert)
		assert.ErrorIs(t, err, nitrite_error.ErrBadPCRValue)
	})

	t.Run("ErrBadPCRValue invalid length", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		doc.PCRs[0] = []byte("invalid length pcr")
		err = attestation.VerifyAttestationDoc(doc, allowSelfSignedCert)
		assert.ErrorIs(t, err, nitrite_error.ErrBadPCRValue)
	})

	t.Run("ErrBadPublicKey", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		doc.PublicKey = make([]byte, attestation.MaxPublicKeyLen+1)
		err = attestation.VerifyAttestationDoc(doc, allowSelfSignedCert)
		assert.ErrorIs(t, err, nitrite_error.ErrBadPublicKey)
	})

	t.Run("ErrBadUserData", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		doc.UserData = make([]byte, attestation.MaxUserDataLen+1)
		err = attestation.VerifyAttestationDoc(doc, allowSelfSignedCert)
		assert.ErrorIs(t, err, nitrite_error.ErrBadUserData)
	})

	t.Run("ErrBadNonce", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		doc.Nonce = make([]byte, attestation.MaxNonceLen+1)
		err = attestation.VerifyAttestationDoc(doc, allowSelfSignedCert)
		assert.ErrorIs(t, err, nitrite_error.ErrBadNonce)
	})

	t.Run("ErrBadCABundle", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		doc.CABundle = make([][]byte, 0)
		err = attestation.VerifyAttestationDoc(doc, allowSelfSignedCert)
		assert.ErrorIs(t, err, nitrite_error.ErrBadCABundle)
	})

	t.Run("ErrBadCABundleItem item nil", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		doc.CABundle[0] = nil
		err = attestation.VerifyAttestationDoc(doc, allowSelfSignedCert)
		assert.ErrorIs(t, err, nitrite_error.ErrBadCABundleItem)
	})

	t.Run("ErrBadCABundleItem item < 1", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		doc.CABundle[0] = make([]byte, 0)
		err = attestation.VerifyAttestationDoc(doc, allowSelfSignedCert)
		assert.ErrorIs(t, err, nitrite_error.ErrBadCABundleItem)
	})

	t.Run("ErrBadCABundleItem item > 1024", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		doc.CABundle[0] = make([]byte, 1025)
		err = attestation.VerifyAttestationDoc(doc, allowSelfSignedCert)
		assert.ErrorIs(t, err, nitrite_error.ErrBadCABundleItem)
	})
}

func TestAttestation_ExtractCertificates(t *testing.T) {
	allowSelfSignedCert := false
	t.Run("happy path", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		cert, certs, certPool, err := attestation.ExtractCertificates(
			doc,
			allowSelfSignedCert,
		)
		assert.NoError(t, err)
		assert.NotNil(t, cert)
		assert.NotNil(t, certs)
		assert.NotNil(t, certPool)
	})

	t.Run("ParseCertificate error", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		doc.Certificate = nil
		cert, certs, certPool, err := attestation.ExtractCertificates(
			doc,
			allowSelfSignedCert,
		)
		assert.Error(t, err)
		assert.Nil(t, cert)
		assert.Nil(t, certs)
		assert.Nil(t, certPool)
	})

	t.Run("ParseCertificate error CABundle", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		doc.CABundle[0] = nil
		cert, certs, certPool, err := attestation.ExtractCertificates(
			doc,
			allowSelfSignedCert,
		)
		assert.Error(t, err)
		assert.Nil(t, cert)
		assert.Nil(t, certs)
		assert.Nil(t, certPool)
	})
}

func TestAttestation_VerifyCertificates(t *testing.T) {
	allowSelfSignedCert := false
	t.Run("happy path", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		cert, _, certPool, err := attestation.ExtractCertificates(
			doc,
			allowSelfSignedCert,
		)
		require.NoError(t, err)

		validTime := time.Date(2023, time.July, 10, 15, 22, 53, 0, time.UTC)
		err = attestation.VerifyCertificates(
			cert,
			certPool,
			nil,
			validTime,
		)
		assert.NoError(t, err)
	})

	t.Run("expired cert", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		cert, _, certPool, err := attestation.ExtractCertificates(
			doc,
			allowSelfSignedCert,
		)
		require.NoError(t, err)

		expiredTime := time.Date(2024, time.July, 10, 15, 22, 53, 0, time.UTC)
		err = attestation.VerifyCertificates(
			cert,
			certPool,
			nil,
			expiredTime,
		)
		assert.ErrorContains(t, err, "certificate has expired")
	})

	t.Run("invalid cert", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		cert, _, certPool, err := attestation.ExtractCertificates(
			doc,
			allowSelfSignedCert,
		)
		require.NoError(t, err)

		invalidTime := time.Date(2022, time.July, 10, 15, 22, 53, 0, time.UTC)
		err = attestation.VerifyCertificates(
			cert,
			certPool,
			nil,
			invalidTime,
		)
		assert.ErrorContains(t, err, "is not yet valid")
	})

	t.Run("nil intermediates", func(t *testing.T) {
		doc, err := makeAttestationDocFromJSON([]byte(nitroStagAttestDocJSON))
		require.NoError(t, err)

		cert, _, _, err := attestation.ExtractCertificates(
			doc,
			allowSelfSignedCert,
		)
		require.NoError(t, err)

		validTime := time.Date(2023, time.July, 10, 15, 22, 53, 0, time.UTC)
		err = attestation.VerifyCertificates(
			cert,
			nil,
			nil,
			validTime,
		)
		assert.ErrorContains(t, err, "signed by unknown authority")
	})
}
