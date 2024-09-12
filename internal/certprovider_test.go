package internal_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/blocky/nitrite"
	"github.com/blocky/nitrite/internal"
	"github.com/blocky/nitrite/mocks"
)

func TestNitroCertProvider_Interfaces(t *testing.T) {
	var _ nitrite.CertProvider = internal.NewNitroCertProvider()
}

func TestNewNitroCertProvider(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		// when
		cp := internal.NewNitroCertProvider()

		// then
		require.NotNil(t, cp)
	})
}

func TestNitroCertProvider_Roots(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		// given
		cp := internal.NewNitroCertProvider()
		assert.Empty(t, cp)

		// when
		gotRoots, err := cp.Roots()

		// then
		require.NoError(t, err)
		assert.False(t, gotRoots.Equal(x509.NewCertPool())) // check not empty
		assert.NotEmpty(t, cp)                              // cp.certs got set
	})
}

func TestNitroCertProvider_RootsWithCerts(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		// given
		cp := internal.NewNitroCertProvider()

		// when
		gotRoots, err := cp.RootsWithCerts(
			internal.AWSNitroEnclavesRootZip,
			internal.AWSNitroEnclavesRootSHA256Hex,
			internal.UnzipRoots,
		)

		// then
		require.NoError(t, err)
		assert.False(t, gotRoots.Equal(x509.NewCertPool())) // check not empty
	})

	t.Run("incorrect roots digest", func(t *testing.T) {
		// given
		cp := internal.NewNitroCertProvider()

		// when
		_, err := cp.RootsWithCerts(
			internal.AWSNitroEnclavesRootZip,
			"invalid digest",
			internal.UnzipRoots,
		)

		// then
		assert.ErrorContains(t, err, "digest mismatch")
	})

	t.Run("cannot unzip root", func(t *testing.T) {
		// given
		cp := internal.NewNitroCertProvider()
		zipBytes := []byte("invalid zip bytes")
		zipBytesDigest := sha256.Sum256(zipBytes)
		zipBytesDigestHex := hex.EncodeToString(zipBytesDigest[:])

		// when
		_, err := cp.RootsWithCerts(
			zipBytes,
			zipBytesDigestHex,
			internal.UnzipRoots,
		)

		// then
		assert.ErrorContains(t, err, "unzipping roots")
	})

	appendCertErrorTests := []struct {
		name    string
		pemCert []byte
	}{
		{"empty", []byte{}},
		{"invalid", []byte("invalid PEM bytes")},
		{"nil", nil},
	}
	for _, tt := range appendCertErrorTests {
		t.Run("cannot append "+tt.name+" PEM cert", func(t *testing.T) {
			// given
			cp := internal.NewNitroCertProvider()
			unzipRoots := mocks.NewInternalUnzipRootsFunc(t)

			// expecting
			unzipRoots.EXPECT().
				Execute(mock.Anything).
				Return(tt.pemCert, nil)

			// when
			_, err := cp.RootsWithCerts(
				internal.AWSNitroEnclavesRootZip,
				internal.AWSNitroEnclavesRootSHA256Hex,
				unzipRoots.Execute,
			)

			// then
			assert.ErrorContains(t, err, "appending cert")
		})
	}
}

func TestFetchingNitroCertProvider_Interfaces(t *testing.T) {
	var _ nitrite.CertProvider = internal.NewFetchingNitroCertProvider()
}

func TestNewFetchingNitroCertProvider(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		// when
		cp := internal.NewFetchingNitroCertProvider()

		// then
		require.NotEmpty(t, cp)
	})
}

func TestFetchingNitroCertProvider_Roots(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		// given
		roundTripper := mocks.NewHttpRoundTripper(t)
		client := http.Client{Transport: roundTripper}
		cp := internal.NewFetchingNitroCertProviderWithClient(&client)

		// expecting
		recorder := httptest.NewRecorder()
		recorder.WriteHeader(http.StatusOK)
		_, err := recorder.Write(internal.AWSNitroEnclavesRootZip)
		require.NoError(t, err)
		roundTripper.EXPECT().
			RoundTrip(mock.Anything).
			Return(recorder.Result(), nil)

		// when
		gotRoots, err := cp.Roots()

		// then
		require.NoError(t, err)
		assert.False(t, gotRoots.Equal(x509.NewCertPool())) // check not empty
	})

	t.Run("cannot fetch roots", func(t *testing.T) {
		// given
		roundTripper := mocks.NewHttpRoundTripper(t)
		client := http.Client{Transport: roundTripper}
		cp := internal.NewFetchingNitroCertProviderWithClient(&client)

		// expecting
		roundTripper.EXPECT().
			RoundTrip(mock.Anything).
			Return(nil, assert.AnError)

		// when
		_, err := cp.Roots()

		// then
		assert.ErrorIs(t, err, assert.AnError)
		assert.ErrorContains(t, err, "fetching root file")
	})

	t.Run("cannot create certs", func(t *testing.T) {
		// given
		roundTripper := mocks.NewHttpRoundTripper(t)
		client := http.Client{Transport: roundTripper}
		cp := internal.NewFetchingNitroCertProviderWithClient(&client)

		// expecting
		recorder := httptest.NewRecorder()
		recorder.WriteHeader(http.StatusOK)
		_, err := recorder.Write(nil)
		require.NoError(t, err)
		roundTripper.EXPECT().
			RoundTrip(mock.Anything).
			Return(recorder.Result(), nil)

		// when
		_, err = cp.Roots()

		// then
		assert.ErrorContains(t, err, "creating certs")
	})
}

func TestSelfSignedCertProvider_Interfaces(t *testing.T) {
	var _ nitrite.CertProvider = internal.NewSelfSignedCertProvider()
}

func TestNewSelfSignedCertProvider(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		// when
		cp := internal.NewSelfSignedCertProvider()

		// then
		require.NotNil(t, cp)
	})
}

func TestSelfSignedCertProvider_Roots(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		// given
		cp := internal.NewSelfSignedCertProvider()
		assert.Empty(t, cp)

		// when
		gotRoots, err := cp.Roots()

		// then
		require.NoError(t, err)
		assert.False(t, gotRoots.Equal(x509.NewCertPool())) // check not empty
		assert.NotEmpty(t, cp)                              // cp.certs got set
	})

	errorTests := []struct {
		name    string
		derCert []byte
	}{
		{"empty", []byte{}},
		{"invalid", []byte("invalid DER bytes")},
		{"nil", nil},
	}
	for _, tt := range errorTests {
		t.Run("cannot append "+tt.name+" cert", func(t *testing.T) {
			// given
			cp := internal.NewSelfSignedCertProvider()

			// when
			_, err := cp.RootWithCert(tt.derCert)

			// then
			assert.ErrorContains(t, err, "appending cert")
		})
	}
}
