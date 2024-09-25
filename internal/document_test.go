package internal_test

import (
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/blocky/nitrite/internal"
	"github.com/blocky/nitrite/mocks"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

		cosePayload := internal.CosePayload{}
		err = cbor.Unmarshal(attestation, &cosePayload)
		require.NoError(t, err)

		err = cbor.Unmarshal(cosePayload.Payload, &docs[i])
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
			name: "happy path - debug nitro",
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
			_, err := tt.doc.Verify(
				tt.certProvider,
				internal.WithAttestationTime(),
			)

			// then
			require.NoError(t, err)
		})
	}
}
func TestDocument_CheckMandatoryFields(t *testing.T) {
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
			err := tt.doc.CheckMandatoryFields()

			// then
			require.NoError(t, err)
		})
	}

	t.Run("missing module id", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.ModuleID = ""

		// when
		err := doc.CheckMandatoryFields()

		// then
		assert.ErrorContains(t, err, "missing module id")
	})

	t.Run("missing digest", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.Digest = ""

		// when
		err := doc.CheckMandatoryFields()

		// then
		assert.ErrorContains(t, err, "missing digest")
	})

	t.Run("missing timestamp", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.Timestamp = 0

		// when
		err := doc.CheckMandatoryFields()

		// then
		assert.ErrorContains(t, err, "missing timestamp")
	})

	t.Run("missing pcrs", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.PCRs = nil

		// when
		err := doc.CheckMandatoryFields()

		// then
		assert.ErrorContains(t, err, "missing pcrs")
	})

	t.Run("missing certificate", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.Certificate = nil

		// when
		err := doc.CheckMandatoryFields()

		// then
		assert.ErrorContains(t, err, "missing certificate")
	})

	t.Run("wrong digest type", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.Digest = "wrong"

		// when
		err := doc.CheckMandatoryFields()

		// then
		assert.ErrorContains(t, err, "expected 'SHA384' digest but got")
	})

	t.Run("too few pcrs", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.PCRs = make(map[uint][]byte, 0)

		// when
		err := doc.CheckMandatoryFields()

		// then
		assert.ErrorContains(t, err, "expected 1 to 32 pcrs but got")
	})

	t.Run("too many pcrs", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.PCRs = make(map[uint][]byte, 33)

		// when
		err := doc.CheckMandatoryFields()

		// then
		assert.ErrorContains(t, err, "expected 1 to 32 pcrs but got")
	})

	t.Run("pcr key out of range", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.PCRs = map[uint][]byte{33: nil}

		// when
		err := doc.CheckMandatoryFields()

		// then
		assert.ErrorContains(t, err, "is out of range")
	})

	t.Run("pcr is nil", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.PCRs = map[uint][]byte{0: nil}

		// when
		err := doc.CheckMandatoryFields()

		// then
		assert.ErrorContains(t, err, "is nil")
	})

	t.Run("pcr incorrect length", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.PCRs = map[uint][]byte{0: make([]byte, 1)}

		// when
		err := doc.CheckMandatoryFields()

		// then
		assert.ErrorContains(t, err, "expected pcr len")
	})
}

func TestDocument_CheckOptionalFields(t *testing.T) {
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
			err := tt.doc.CheckOptionalFields()

			// then
			require.NoError(t, err)
		})
	}

	t.Run("public key too long", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.PublicKey = make([]byte, internal.MaxPublicKeyLen+1)

		// when
		err := doc.CheckOptionalFields()

		// then
		assert.ErrorContains(t, err, "max public key len is")
	})

	t.Run("user data too long", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.UserData = make([]byte, 1025)

		// when
		err := doc.CheckOptionalFields()

		// then
		assert.ErrorContains(t, err, "max user data len is")
	})

	t.Run("nonce too long", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.Nonce = make([]byte, 1025)

		// when
		err := doc.CheckOptionalFields()

		// then
		assert.ErrorContains(t, err, "max nonce len is")
	})
}

func TestDocument_CheckCertificates(t *testing.T) {
	nitroDoc, debugNitroDoc, selfSignedDoc := initDocuments(t)
	documents := map[string]struct {
		doc          internal.Document
		time         time.Time
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
			_, err := documents[key].doc.CheckCertificates(
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
			_, err := documents[key].doc.CheckCertificates(
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
			_, err := documents[key].doc.CheckCertificates(
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
			_, err := documents[key].doc.CheckCertificates(
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
				_, err := documents[key].doc.CheckCertificates(
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
		_, err := doc.CheckCertificates(nil, nil)

		// then
		assert.ErrorContains(t, err, "parsing cert")
	})

	t.Run("missing cabundle", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.CABundle = nil

		// when
		_, err := doc.CheckCertificates(nil, nil)

		// then
		assert.ErrorContains(t, err, "missing cabundle")
	})

	t.Run("missing cabundle item", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.CABundle = [][]byte{nil}

		// when
		_, err := doc.CheckCertificates(nil, nil)

		// then
		assert.ErrorContains(t, err, "cabundle item")
	})

	t.Run("cabundle item too short", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.CABundle = [][]byte{make([]byte, 0)}

		// when
		_, err := doc.CheckCertificates(nil, nil)

		// then
		assert.ErrorContains(t, err, "cabundle item")
	})

	t.Run("cabundle item too long", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.CABundle = [][]byte{make([]byte, 1025)}

		// when
		_, err := doc.CheckCertificates(nil, nil)

		// then
		assert.ErrorContains(t, err, "cabundle item")
	})

	t.Run("parsing intermediate", func(t *testing.T) {
		// given
		doc := nitroDoc
		doc.CABundle = [][]byte{make([]byte, 1)}

		// when
		_, err := doc.CheckCertificates(nil, nil)

		// then
		assert.ErrorContains(t, err, "parsing intermediate")
	})
}
