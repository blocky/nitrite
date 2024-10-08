package internal_test

import (
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/blocky/nitrite/internal"
	"github.com/blocky/nitrite/mocks"
)

func initDocuments(t *testing.T) (
	internal.Document,
	internal.Document,
	internal.Document,
) {
	attb64Strings := []string{
		internal.NitroAttestationB64,
		internal.DebugNitroAttestationB64,
		internal.SelfSignedAttestationB64,
	}
	docs := make([]internal.Document, len(attb64Strings))

	for i, att64String := range attb64Strings {
		attestation, err := base64.StdEncoding.DecodeString(att64String)
		require.NoError(t, err)

		coseSign1 := internal.CoseSign1{}
		err = coseSign1.UnmarshalBinary(attestation)
		require.NoError(t, err)

		err = docs[i].UnmarshalBinary(coseSign1.Payload)
		require.NoError(t, err)
	}
	return docs[0], docs[1], docs[2]
}

func TestDocument_CreatedAt(t *testing.T) {
	happyPathTests := []struct {
		name      string
		timestamp uint64
		wantTime  time.Time
	}{
		{
			"happy path",
			uint64(internal.NitroAttestationTime.UnixMilli()),
			internal.NitroAttestationTime,
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
			doc := internal.Document{Timestamp: tt.timestamp}

			// when
			gotTime := doc.CreatedAt()

			// then
			assert.Equal(t, tt.wantTime.UTC(), gotTime.UTC())
		})
	}
}

func TestDocument_Debug(t *testing.T) {
	happyPathTests := []struct {
		name      string
		pcrs      map[uint][]byte
		wantDebug bool
	}{
		{"happy path - in debug mode", map[uint][]byte{0: {0x00}}, true},
		{"happy path - not in debug mode", map[uint][]byte{0: {0xAB}}, false},
	}
	for _, tt := range happyPathTests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			doc := internal.Document{PCRs: tt.pcrs}

			// when
			gotDebug, err := doc.Debug()

			// then
			assert.NoError(t, err)
			assert.Equal(t, tt.wantDebug, gotDebug)
		})
	}

	t.Run("no PCR0", func(t *testing.T) {
		// given
		doc := internal.Document{PCRs: map[uint][]byte{}}

		// when
		_, err := doc.Debug()

		// then
		assert.ErrorContains(t, err, "PCR0 not found")
	})
}

func TestDocument_Verify(t *testing.T) {
	nitroDoc, debugNitroDoc, selfSignedDoc := initDocuments(t)
	happyPathTests := []struct {
		name         string
		doc          internal.Document
		certProvider internal.CertProvider
	}{
		{
			name: "happy path - nitro",
			doc:  nitroDoc,
			certProvider: internal.NewNitroCertProvider(
				internal.NewEmbeddedRootCertZipReader(),
			),
		},
		{
			name: "happy path - debug",
			doc:  debugNitroDoc,
			certProvider: internal.NewNitroCertProvider(
				internal.NewEmbeddedRootCertZipReader(),
			),
		},
		{
			name:         "happy path - self signed",
			doc:          selfSignedDoc,
			certProvider: internal.NewSelfSignedCertProvider(),
		},
	}

	for _, tt := range happyPathTests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			_, err := tt.doc.Verify(tt.certProvider, internal.WithAttestationTime())

			// then
			require.NoError(t, err)
		})
	}

	t.Run("verifying mandatory fields", func(t *testing.T) {
		// given
		doc := internal.Document{}

		// when
		_, err := doc.Verify(
			internal.NewNitroCertProvider(
				internal.NewEmbeddedRootCertZipReader(),
			),
			internal.WithAttestationTime(),
		)

		// then
		assert.ErrorContains(t, err, "verifying mandatory fields")
	})

	t.Run("verifying optional fields", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.PublicKey = make([]byte, internal.MaxPublicKeyLen+1)

		// when
		_, err := doc.Verify(
			internal.NewNitroCertProvider(
				internal.NewEmbeddedRootCertZipReader(),
			),
			internal.WithAttestationTime(),
		)

		// then
		assert.ErrorContains(t, err, "verifying optional fields")
	})

	t.Run("verifying certificates", func(t *testing.T) {
		// when
		_, err := nitroDoc.Verify(
			internal.NewSelfSignedCertProvider(),
			internal.WithAttestationTime(),
		)

		// then
		assert.ErrorContains(t, err, "verifying certificates")
	})
}

func TestDocument_VerifyMandatoryFields(t *testing.T) {
	nitroDoc, debugNitroDoc, selfSignedDoc := initDocuments(t)
	happyPathTests := []struct {
		name string
		doc  internal.Document
	}{
		{
			name: "happy path - nitro",
			doc:  nitroDoc,
		},
		{
			name: "happy path - debug nitro",
			doc:  debugNitroDoc,
		},
		{
			name: "happy path - self signed",
			doc:  selfSignedDoc,
		},
	}

	for _, tt := range happyPathTests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			err := tt.doc.VerifyMandatoryFields()

			// then
			require.NoError(t, err)
		})
	}

	t.Run("missing module id", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.ModuleID = ""

		// when
		err := doc.VerifyMandatoryFields()

		// then
		assert.ErrorContains(t, err, "missing module id")
	})

	t.Run("missing digest", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.Digest = ""

		// when
		err := doc.VerifyMandatoryFields()

		// then
		assert.ErrorContains(t, err, "missing digest")
	})

	t.Run("missing timestamp", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.Timestamp = 0

		// when
		err := doc.VerifyMandatoryFields()

		// then
		assert.ErrorContains(t, err, "missing timestamp")
	})

	t.Run("missing pcrs", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.PCRs = nil

		// when
		err := doc.VerifyMandatoryFields()

		// then
		assert.ErrorContains(t, err, "missing pcrs")
	})

	t.Run("missing certificate", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.Certificate = nil

		// when
		err := doc.VerifyMandatoryFields()

		// then
		assert.ErrorContains(t, err, "missing certificate")
	})

	t.Run("wrong digest type", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.Digest = "wrong"

		// when
		err := doc.VerifyMandatoryFields()

		// then
		assert.ErrorContains(t, err, "expected 'SHA384' digest but got")
	})

	t.Run("too few pcrs", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.PCRs = make(map[uint][]byte, 0)

		// when
		err := doc.VerifyMandatoryFields()

		// then
		assert.ErrorContains(t, err, "expected 1 to 32 pcrs but got")
	})

	t.Run("too many pcrs", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.PCRs = make(map[uint][]byte, 33)

		// when
		err := doc.VerifyMandatoryFields()

		// then
		assert.ErrorContains(t, err, "expected 1 to 32 pcrs but got")
	})

	t.Run("pcr key out of range", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.PCRs = map[uint][]byte{33: nil}

		// when
		err := doc.VerifyMandatoryFields()

		// then
		assert.ErrorContains(t, err, "is out of range")
	})

	t.Run("pcr is nil", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.PCRs = map[uint][]byte{0: nil}

		// when
		err := doc.VerifyMandatoryFields()

		// then
		assert.ErrorContains(t, err, "is nil")
	})

	t.Run("pcr incorrect length", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.PCRs = map[uint][]byte{0: make([]byte, 1)}

		// when
		err := doc.VerifyMandatoryFields()

		// then
		assert.ErrorContains(t, err, "expected pcr len")
	})
}

func TestDocument_VerifyOptionalFields(t *testing.T) {
	nitroDoc, debugNitroDoc, selfSignedDoc := initDocuments(t)
	happyPathTests := []struct {
		name string
		doc  internal.Document
	}{
		{
			name: "happy path - nitro",
			doc:  nitroDoc,
		},
		{
			name: "happy path - debug nitro",
			doc:  debugNitroDoc,
		},
		{
			name: "happy path - self signed",
			doc:  selfSignedDoc,
		},
	}

	for _, tt := range happyPathTests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			err := tt.doc.VerifyOptionalFields()

			// then
			require.NoError(t, err)
		})
	}

	t.Run("public key too long", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.PublicKey = make([]byte, internal.MaxPublicKeyLen+1)

		// when
		err := doc.VerifyOptionalFields()

		// then
		assert.ErrorContains(t, err, "max public key len is")
	})

	t.Run("user data too long", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.UserData = make([]byte, internal.MaxUserDataLen+1)

		// when
		err := doc.VerifyOptionalFields()

		// then
		assert.ErrorContains(t, err, "max user data len is")
	})

	t.Run("nonce too long", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.Nonce = make([]byte, internal.MaxNonceLen+1)

		// when
		err := doc.VerifyOptionalFields()

		// then
		assert.ErrorContains(t, err, "max nonce len is")
	})
}

func TestDocument_VerifyCertificates(t *testing.T) {
	nitroDoc, debugNitroDoc, selfSignedDoc := initDocuments(t)
	documents := map[string]struct {
		doc          internal.Document
		certProvider internal.CertProvider
	}{
		"nitro": {
			doc: nitroDoc,
			certProvider: internal.NewNitroCertProvider(
				internal.NewEmbeddedRootCertZipReader(),
			),
		},
		"debug": {
			doc: debugNitroDoc,
			certProvider: internal.NewNitroCertProvider(
				internal.NewEmbeddedRootCertZipReader(),
			),
		},
		"self-signed": {
			doc:          selfSignedDoc,
			certProvider: internal.NewSelfSignedCertProvider(),
		},
	}

	for key := range documents {
		t.Run("happy path", func(t *testing.T) {
			t.Log(key)

			// when
			_, err := documents[key].doc.VerifyCertificates(
				documents[key].certProvider,
				internal.WithAttestationTime(),
			)

			// then
			require.NoError(t, err)
		})

		t.Run("cannot get root certificates", func(t *testing.T) {
			t.Log(key)

			// given
			certProvider := mocks.NewInternalCertProvider(t)

			// expecting
			certProvider.EXPECT().Roots().Return(nil, assert.AnError)

			// when
			_, err := documents[key].doc.VerifyCertificates(
				certProvider,
				internal.WithAttestationTime(),
			)

			// then
			assert.ErrorIs(t, err, assert.AnError)
			assert.ErrorContains(t, err, "getting root certificates")
		})

		t.Run("unknown signing authority - nil roots", func(t *testing.T) {
			t.Log(key)

			// given
			certProvider := mocks.NewInternalCertProvider(t)

			// expecting
			certProvider.EXPECT().Roots().Return(nil, nil)

			// when
			_, err := documents[key].doc.VerifyCertificates(
				certProvider,
				internal.WithAttestationTime(),
			)

			// then
			assert.ErrorContains(t, err, "verifying certificate")
		})

		t.Run("unknown signing authority - empty roots", func(t *testing.T) {
			t.Log(key)

			// given
			certProvider := mocks.NewInternalCertProvider(t)

			// expecting
			certProvider.EXPECT().Roots().Return(x509.NewCertPool(), nil)

			// when
			_, err := documents[key].doc.VerifyCertificates(
				certProvider,
				internal.WithAttestationTime(),
			)

			// then
			assert.ErrorContains(t, err, "verifying certificate")
		})

		timeOutOfBoundsTests := []struct {
			name        string
			timeOpt     internal.VerificationTimeFunc
			errContains string
		}{
			{
				"certificate expired",
				internal.WithTime(time.Date(10000, 0, 0, 0, 0, 0, 0, time.UTC)),
				"verifying certificate",
			},
			{
				"certificate not yet valid",
				internal.WithTime(time.Date(1970, 0, 0, 0, 0, 0, 0, time.UTC)),
				"verifying certificate",
			},
			{
				"zero time",
				internal.WithTime(time.Time{}),
				"verification time is 0",
			},
		}
		for _, tt := range timeOutOfBoundsTests {
			t.Run(tt.name, func(t *testing.T) {
				t.Log(key)

				// when
				_, err := documents[key].doc.VerifyCertificates(
					documents[key].certProvider,
					tt.timeOpt,
				)

				// then
				assert.ErrorContains(t, err, tt.errContains)
			})
		}
	}

	t.Run("parsing cert", func(t *testing.T) {
		// given
		doc := internal.Document{}

		// when
		_, err := doc.VerifyCertificates(nil, nil)

		// then
		assert.ErrorContains(t, err, "parsing cert")
	})

	t.Run("missing cabundle", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.CABundle = nil

		// when
		_, err := doc.VerifyCertificates(nil, nil)

		// then
		assert.ErrorContains(t, err, "missing cabundle")
	})

	t.Run("missing cabundle item", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.CABundle = [][]byte{nil}

		// when
		_, err := doc.VerifyCertificates(nil, nil)

		// then
		assert.ErrorContains(t, err, "cabundle item '0' expected len is")
	})

	t.Run("cabundle item too short", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.CABundle = [][]byte{make([]byte, 0)}

		// when
		_, err := doc.VerifyCertificates(nil, nil)

		// then
		assert.ErrorContains(t, err, "cabundle item '0' expected len is")
	})

	t.Run("cabundle item too long", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.CABundle = [][]byte{make([]byte, 1025)}

		// when
		_, err := doc.VerifyCertificates(nil, nil)

		// then
		assert.ErrorContains(t, err, "cabundle item '0' expected len is")
	})

	t.Run("parsing intermediate certificate", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.CABundle = [][]byte{make([]byte, 1)}

		// when
		_, err := doc.VerifyCertificates(nil, nil)

		// then
		assert.ErrorContains(t, err, "parsing intermediate")
	})
}
