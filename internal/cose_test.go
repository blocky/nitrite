package internal_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/blocky/nitrite/internal"
)

func TestCoseSign1_Verify(t *testing.T) {
	nitroAtt, debugAtt, selfAtt := initAttestations(t)
	happyPathTests := []struct {
		name         string
		attestation  []byte
		certProvider internal.CertProvider
	}{
		{
			name:        "happy path - nitro",
			attestation: nitroAtt,
			certProvider: internal.NewNitroCertProvider(
				internal.NewEmbeddedRootCertZipReader(),
			),
		},
		{
			name:        "happy path - debug",
			attestation: debugAtt,
			certProvider: internal.NewNitroCertProvider(
				internal.NewEmbeddedRootCertZipReader(),
			),
		},
		{
			name:         "happy path - self signed",
			attestation:  selfAtt,
			certProvider: internal.NewSelfSignedCertProvider(),
		},
	}
	for _, tt := range happyPathTests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			coseSign1 := internal.CoseSign1{}
			err := coseSign1.UnmarshalBinary(tt.attestation)
			require.NoError(t, err)

			doc := internal.Document{}
			err = doc.UnmarshalBinary(coseSign1.Payload)
			require.NoError(t, err)

			certificates, err := doc.Verify(
				tt.certProvider,
				internal.WithAttestationTime(),
			)
			require.NoError(t, err)

			// when
			err = coseSign1.Verify(certificates[0].PublicKey.(*ecdsa.PublicKey))

			// then
			assert.NoError(t, err)
		})
	}

	t.Run("verifying signature", func(t *testing.T) {
		// given
		coseSign1 := internal.CoseSign1{}
		err := coseSign1.UnmarshalBinary(nitroAtt)
		require.NoError(t, err)

		privKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		require.NoError(t, err)

		// when
		err = coseSign1.Verify(&privKey.PublicKey)

		// then
		assert.ErrorContains(t, err, "verifying signature")
	})

	t.Run("missing protected", func(t *testing.T) {
		// given
		coseSign1 := internal.CoseSign1{}

		// when
		err := coseSign1.Verify(nil)

		// then
		assert.ErrorContains(t, err, "missing cose protected headers")
	})

	t.Run("missing payload", func(t *testing.T) {
		// given
		coseSign1 := internal.CoseSign1{Protected: []byte{0}}

		// when
		err := coseSign1.Verify(nil)

		// then
		assert.ErrorContains(t, err, "missing cose payload")
	})

	t.Run("missing signature", func(t *testing.T) {
		// given
		coseSign1 := internal.CoseSign1{
			Protected: []byte{0},
			Payload:   []byte{0},
		}

		// when
		err := coseSign1.Verify(nil)

		// then
		assert.ErrorContains(t, err, "missing cose signature")
	})
}

func TestCoseSign1_VerifySignature(t *testing.T) {
	nitroAtt, debugAtt, selfAtt := initAttestations(t)
	happyPathTests := []struct {
		name         string
		attestation  []byte
		certProvider internal.CertProvider
	}{
		{
			name:        "happy path - nitro",
			attestation: nitroAtt,
			certProvider: internal.NewNitroCertProvider(
				internal.NewEmbeddedRootCertZipReader(),
			),
		},
		{
			name:        "happy path - debug",
			attestation: debugAtt,
			certProvider: internal.NewNitroCertProvider(
				internal.NewEmbeddedRootCertZipReader(),
			),
		},
		{
			name:         "happy path - self signed",
			attestation:  selfAtt,
			certProvider: internal.NewSelfSignedCertProvider(),
		},
	}
	for _, tt := range happyPathTests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			coseSign1 := internal.CoseSign1{}
			err := coseSign1.UnmarshalBinary(tt.attestation)
			require.NoError(t, err)

			doc := internal.Document{}
			err = doc.UnmarshalBinary(coseSign1.Payload)
			require.NoError(t, err)

			certificates, err := doc.Verify(
				tt.certProvider,
				internal.WithAttestationTime(),
			)
			require.NoError(t, err)

			// when
			err = coseSign1.VerifySignature(
				certificates[0].PublicKey.(*ecdsa.PublicKey),
			)

			// then
			assert.NoError(t, err)
		})
	}

	t.Run("nil public key", func(t *testing.T) {
		// given
		coseSign1 := internal.CoseSign1{}

		// when
		err := coseSign1.VerifySignature(nil)

		// then
		assert.ErrorContains(t, err, "public key is nil")
	})

	t.Run("error getting signing algorithm from CoseSign1", func(t *testing.T) {
		// given
		coseSign1 := internal.CoseSign1{}
		privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		// when
		err = coseSign1.VerifySignature(&privKey.PublicKey)

		// then
		assert.ErrorContains(t, err, "extracting signing algorithm")
	})

	t.Run("incorrect public key signing algorithm", func(t *testing.T) {
		// given
		coseSign1 := internal.CoseSign1{}
		err := coseSign1.UnmarshalBinary(nitroAtt)
		require.NoError(t, err)

		privKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		require.NoError(t, err)

		// when
		err = coseSign1.VerifySignature(&privKey.PublicKey)

		// then
		assert.ErrorContains(t, err, "does not match public key signing alg")
	})

	t.Run("incorrect signature length", func(t *testing.T) {
		// given
		coseSign1 := internal.CoseSign1{}
		err := coseSign1.UnmarshalBinary(nitroAtt)
		require.NoError(t, err)
		coseSign1.Signature = nil

		privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		// when
		err = coseSign1.VerifySignature(&privKey.PublicKey)

		// then
		assert.ErrorContains(t, err, "expected signature len")
	})

	t.Run("incorrect public key", func(t *testing.T) {
		// given
		coseSign1 := internal.CoseSign1{}
		err := coseSign1.UnmarshalBinary(nitroAtt)
		require.NoError(t, err)
		privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		// when
		err = coseSign1.VerifySignature(&privKey.PublicKey)

		// then
		assert.ErrorContains(t, err, "failed to verify ecdsa signature")
	})
}

func TestCoseSign1_GetSigningAlgorithm(t *testing.T) {
	nitroAtt, debugAtt, selfAtt := initAttestations(t)
	happyPathTests := []struct {
		name        string
		attestation []byte
	}{
		{
			name:        "happy path - nitro",
			attestation: nitroAtt,
		},
		{
			name:        "happy path - debug",
			attestation: debugAtt,
		},
		{
			name:        "happy path - self signed",
			attestation: selfAtt,
		},
	}
	for _, tt := range happyPathTests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			coseSign1 := internal.CoseSign1{}
			err := coseSign1.UnmarshalBinary(tt.attestation)
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
		coseSign1 := internal.CoseSign1{}
		err := coseSign1.UnmarshalBinary(nitroAtt)
		require.NoError(t, err)
		coseSign1.Protected = nil

		// when
		signingAlg, err := coseSign1.GetSigningAlgorithm()

		// then
		assert.ErrorContains(t, err, "unmarshaling cose protected header")
		assert.Equal(t, signingAlg, internal.MissingSigningAlgorithm)
	})

	t.Run("unsupported signing algorithm int", func(t *testing.T) {
		// given
		coseSign1 := internal.CoseSign1{}
		err := coseSign1.UnmarshalBinary(nitroAtt)
		require.NoError(t, err)

		coseHeader := internal.CoseHeader{}
		coseHeader.Alg = int64(-8)
		headerBytes, err := cbor.Marshal(coseHeader)
		require.NoError(t, err)
		coseSign1.Protected = headerBytes

		// when
		signingAlg, err := coseSign1.GetSigningAlgorithm()

		// then
		assert.ErrorContains(t, err, "unsupported signing algorithm int")
		assert.Equal(t, signingAlg, internal.BadSigningAlgorithm)
	})

	t.Run("unsupported signing algorithm string", func(t *testing.T) {
		// given
		coseSign1 := internal.CoseSign1{}
		err := coseSign1.UnmarshalBinary(nitroAtt)
		require.NoError(t, err)

		coseHeader := internal.CoseHeader{}
		coseHeader.Alg = "unsupported signing algorithm"
		headerBytes, err := cbor.Marshal(coseHeader)
		require.NoError(t, err)
		coseSign1.Protected = headerBytes

		// when
		signingAlg, err := coseSign1.GetSigningAlgorithm()

		// then
		assert.ErrorContains(t, err, "unsupported signing algorithm string")
		assert.Equal(t, signingAlg, internal.BadSigningAlgorithm)
	})

	t.Run("unsupported signing algorithm type", func(t *testing.T) {
		// given
		coseSign1 := internal.CoseSign1{}
		err := coseSign1.UnmarshalBinary(nitroAtt)
		require.NoError(t, err)

		coseHeader := internal.CoseHeader{}
		headerBytes, err := cbor.Marshal(coseHeader)
		require.NoError(t, err)
		coseSign1.Protected = headerBytes

		// when
		signingAlg, err := coseSign1.GetSigningAlgorithm()

		// then
		assert.ErrorContains(t, err, "missing or wrong signing algorithm type")
		assert.Equal(t, signingAlg, internal.MissingSigningAlgorithm)
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
