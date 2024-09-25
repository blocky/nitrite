package internal_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/blocky/nitrite/internal"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakeCoseSign1FromBytes(t *testing.T) {
	happyPathTests := []struct {
		name           string
		attestationB64 string
	}{
		{
			"happy path - nitro",
			internal.NitroAttestationB64,
		},
		{
			"happy path - debug",
			internal.DebugNitroAttestationB64,
		},
		{
			"happy path - self signed",
			internal.SelfSignedAttestationB64,
		},
	}
	for _, tt := range happyPathTests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			attestation, err := base64.StdEncoding.DecodeString(tt.attestationB64)
			require.NoError(t, err)

			// when
			_, err = internal.MakeCoseSign1FromBytes(attestation)

			// then
			assert.NoError(t, err)
		})
	}

	t.Run("unmarshaling CoseSign1", func(t *testing.T) {
		// given

		// when
		_, err := internal.MakeCoseSign1FromBytes([]byte{0})

		// then
		assert.ErrorContains(t, err, "unmarshaling CoseSign1 from bytes")
	})

	t.Run("missing protected", func(t *testing.T) {
		// given
		coseSign1 := internal.CoseSign1{}
		bytes, err := cbor.Marshal(coseSign1)
		require.NoError(t, err)

		// when
		_, err = internal.MakeCoseSign1FromBytes(bytes)

		// then
		assert.ErrorContains(t, err, "missing cose protected headers")
	})

	t.Run("missing payload", func(t *testing.T) {
		// given
		coseSign1 := internal.CoseSign1{Protected: []byte{0}}
		bytes, err := cbor.Marshal(coseSign1)
		require.NoError(t, err)

		// when
		_, err = internal.MakeCoseSign1FromBytes(bytes)

		// then
		assert.ErrorContains(t, err, "missing cose payload")
	})

	t.Run("missing signature", func(t *testing.T) {
		// given
		coseSign1 := internal.CoseSign1{
			Protected: []byte{0},
			Payload:   []byte{0},
		}
		bytes, err := cbor.Marshal(coseSign1)
		require.NoError(t, err)

		// when
		_, err = internal.MakeCoseSign1FromBytes(bytes)

		// then
		assert.ErrorContains(t, err, "missing cose signature")
	})
}

func TestCoseSign1_CheckSignature(t *testing.T) {
	happyPathTests := []struct {
		name           string
		attestationB64 string
		certProvider   internal.CertProvider
	}{
		{
			name:           "happy path - nitro",
			attestationB64: internal.NitroAttestationB64,
			certProvider: internal.NewNitroCertProvider(
				internal.NewEmbeddedRootCertZipReader(),
			),
		},
		{
			name:           "happy path - debug",
			attestationB64: internal.DebugNitroAttestationB64,
			certProvider: internal.NewNitroCertProvider(
				internal.NewEmbeddedRootCertZipReader(),
			),
		},
		{
			name:           "happy path - self signed",
			attestationB64: internal.SelfSignedAttestationB64,
			certProvider:   internal.NewSelfSignedCertProvider(),
		},
	}
	for _, tt := range happyPathTests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			attestation, err := base64.StdEncoding.DecodeString(tt.attestationB64)
			require.NoError(t, err)

			coseSign1, err := internal.MakeCoseSign1FromBytes(attestation)
			require.NoError(t, err)

			doc, err := internal.MakeDocumentFromBytes(coseSign1.Payload)
			require.NoError(t, err)

			certificates, err := doc.CheckCertificates(
				tt.certProvider,
				internal.WithAttestationTime(),
			)
			require.NoError(t, err)

			// when
			_, err = coseSign1.CheckSignature(
				certificates[0].PublicKey.(*ecdsa.PublicKey),
			)

			// then
			assert.NoError(t, err)
		})
	}

	t.Run("error getting signing algorithm from CoseSign1", func(t *testing.T) {
		// given
		coseSign1 := internal.CoseSign1{}

		// when
		_, err := coseSign1.CheckSignature(nil)

		// then
		assert.ErrorContains(t, err, "extracting signing algorithm")
	})

	t.Run("incorrect public key signing algorithm", func(t *testing.T) {
		// given
		attestation, err := base64.StdEncoding.DecodeString(internal.NitroAttestationB64)
		require.NoError(t, err)

		coseSign1, err := internal.MakeCoseSign1FromBytes(attestation)
		require.NoError(t, err)

		privKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		require.NoError(t, err)

		// when
		_, err = coseSign1.CheckSignature(&privKey.PublicKey)

		// then
		assert.ErrorContains(t, err, "does not match public key signing alg")
	})

	t.Run("incorrect signature length", func(t *testing.T) {
		// given
		attestation, err := base64.StdEncoding.DecodeString(internal.NitroAttestationB64)
		require.NoError(t, err)

		coseSign1, err := internal.MakeCoseSign1FromBytes(attestation)
		require.NoError(t, err)
		coseSign1.Signature = nil

		privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		// when
		_, err = coseSign1.CheckSignature(&privKey.PublicKey)

		// then
		assert.ErrorContains(t, err, "expected signature len")
	})

	t.Run("incorrect public key", func(t *testing.T) {
		// given
		attestation, err := base64.StdEncoding.DecodeString(internal.NitroAttestationB64)
		require.NoError(t, err)

		coseSign1, err := internal.MakeCoseSign1FromBytes(attestation)
		require.NoError(t, err)

		privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		// when
		_, err = coseSign1.CheckSignature(&privKey.PublicKey)

		// then
		assert.ErrorContains(t, err, "failed to verify ecdsa signature")
	})
}

func TestCoseSign1_GetSigningAlgorithm(t *testing.T) {
	happyPathTests := []struct {
		name           string
		attestationB64 string
	}{
		{
			name:           "happy path - nitro",
			attestationB64: internal.NitroAttestationB64,
		},
		{
			name:           "happy path - debug",
			attestationB64: internal.DebugNitroAttestationB64,
		},
		{
			name:           "happy path - self signed",
			attestationB64: internal.SelfSignedAttestationB64,
		},
	}
	for _, tt := range happyPathTests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			attestation, err := base64.StdEncoding.DecodeString(tt.attestationB64)
			require.NoError(t, err)

			coseSign1, err := internal.MakeCoseSign1FromBytes(attestation)
			require.NoError(t, err)

			// when
			signingAlg, err := coseSign1.GetSigningAlgorithm()

			// then
			assert.NoError(t, err)
			assert.Equal(t, signingAlg, internal.ES384)
		})
	}

	t.Run("unmarshaling cose header", func(t *testing.T) {
		// given
		attestation, err := base64.StdEncoding.DecodeString(internal.NitroAttestationB64)
		require.NoError(t, err)

		coseSign1, err := internal.MakeCoseSign1FromBytes(attestation)
		require.NoError(t, err)
		coseSign1.Protected = nil

		// when
		signingAlg, err := coseSign1.GetSigningAlgorithm()

		// then
		assert.ErrorContains(t, err, "unmarshaling cose protected header")
		assert.Equal(t, signingAlg, internal.BadOrMissingAlgorithm)
	})

	t.Run("unsupported signing algorithm type", func(t *testing.T) {
		// given
		attestation, err := base64.StdEncoding.DecodeString(internal.NitroAttestationB64)
		require.NoError(t, err)

		coseSign1, err := internal.MakeCoseSign1FromBytes(attestation)
		require.NoError(t, err)

		coseHeader := internal.CoseHeader{}
		headerBytes, err := cbor.Marshal(coseHeader)
		require.NoError(t, err)
		coseSign1.Protected = headerBytes

		// when
		signingAlg, err := coseSign1.GetSigningAlgorithm()

		// then
		assert.ErrorContains(t, err, "unsupported signing algorithm type")
		assert.Equal(t, signingAlg, internal.BadOrMissingAlgorithm)
	})
}

func TestCoseHeader_AlgorithmInt(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		wantVal := int64(8)
		coseHeader := internal.CoseHeader{
			Alg: wantVal,
		}

		gotVal, ok := coseHeader.AlgorithmInt()

		assert.True(t, ok)
		assert.Equal(t, gotVal, wantVal)
	})

	t.Run("wrong type", func(t *testing.T) {
		wantVal := int64(0)
		coseHeader := internal.CoseHeader{
			Alg: "wrong type",
		}

		gotVal, ok := coseHeader.AlgorithmInt()

		assert.False(t, ok)
		assert.Equal(t, gotVal, wantVal)
	})
}

func TestCoseHeader_AlgorithmString(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		wantVal := "ES384"
		coseHeader := internal.CoseHeader{
			Alg: wantVal,
		}

		gotVal, ok := coseHeader.AlgorithmString()

		assert.True(t, ok)
		assert.Equal(t, gotVal, wantVal)
	})

	t.Run("wrong type", func(t *testing.T) {
		wantVal := ""
		coseHeader := internal.CoseHeader{
			Alg: int64(0),
		}

		gotVal, ok := coseHeader.AlgorithmString()

		assert.False(t, ok)
		assert.Equal(t, gotVal, wantVal)
	})
}
