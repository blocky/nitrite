package internal_test

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/blocky/nitrite/internal"
	"github.com/blocky/nitrite/mocks"
)

func TestUnzipAWSRootCerts(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		// given
		zipped := internal.AWSNitroEnclavesRootZip

		// when
		unzipped, err := internal.UnzipAWSRootCerts(zipped)

		// then
		require.NoError(t, err)
		assert.NotEmpty(t, unzipped)
	})

	unzipErrorTests := []struct {
		name   string
		zipped []byte
	}{
		{"empty", []byte{}},
		{"nil", nil},
		{"invalid", []byte("invalid zip bytes")},
	}
	for _, tt := range unzipErrorTests {
		t.Run("cannot unzip "+tt.name+" zip", func(t *testing.T) {
			// when
			_, err := internal.UnzipAWSRootCerts(tt.zipped)

			// then
			assert.ErrorContains(t, err, "creating zip reader")
		})
	}

	t.Run("unexpected file count", func(t *testing.T) {
		// given
		zipped := &bytes.Buffer{}
		w := zip.NewWriter(zipped)
		_, err := w.Create("file1")
		require.NoError(t, err)
		_, err = w.Create("file2")
		require.NoError(t, err)
		require.NoError(t, w.Close())

		// when
		_, err = internal.UnzipAWSRootCerts(zipped.Bytes())

		// then
		assert.ErrorContains(t, err, "unexpected file count")
	})

	t.Run("unexpected file name", func(t *testing.T) {
		// given
		zipped := &bytes.Buffer{}
		w := zip.NewWriter(zipped)
		_, err := w.Create("file1")
		require.NoError(t, err)
		require.NoError(t, w.Close())

		// when
		_, err = internal.UnzipAWSRootCerts(zipped.Bytes())

		// then
		assert.ErrorContains(t, err, "unexpected file name")
	})
}

func TestNewEmbeddedRootCertZipReader(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		// when
		reader := internal.NewEmbeddedRootCertZipReader()

		// then
		require.NotEmpty(t, reader)

		gotData, err := io.ReadAll(reader)
		require.NoError(t, err)
		assert.Equal(t, internal.AWSNitroEnclavesRootZip, gotData)

		err = reader.Close()
		require.NoError(t, err)
	})
}

func TestNewFetchingRootCertZipReaderWithClient(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		// given
		roundTripper := mocks.NewHttpRoundTripper(t)
		client := http.Client{Transport: roundTripper}

		// expecting
		recorder := httptest.NewRecorder()
		recorder.WriteHeader(http.StatusOK)
		_, err := recorder.Write(internal.AWSNitroEnclavesRootZip)
		require.NoError(t, err)
		roundTripper.EXPECT().
			RoundTrip(mock.Anything).
			Return(recorder.Result(), nil)

		// when
		reader, err := internal.NewFetchingRootCertZipReaderWithClient(&client)

		// then
		require.NoError(t, err)

		gotData, err := io.ReadAll(reader)
		require.NoError(t, err)
		assert.Equal(t, internal.AWSNitroEnclavesRootZip, gotData)

		err = reader.Close()
		require.NoError(t, err)
	})
}

func TestNitroCertProvider_Interfaces(t *testing.T) {
	var _ internal.CertProvider = internal.NewNitroCertProvider(
		internal.NewEmbeddedRootCertZipReader(),
	)
}

func TestNewNitroCertProvider(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		// when
		cp := internal.NewNitroCertProvider(
			internal.NewEmbeddedRootCertZipReader(),
		)

		// then
		assert.NotEmpty(t, cp)
	})
}

func TestNitroCertProvider_Roots(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		// given
		cp := internal.NewNitroCertProvider(
			internal.NewEmbeddedRootCertZipReader(),
		)

		// when
		gotRoots, err := cp.Roots()

		// then
		require.NoError(t, err)
		assert.False(t, gotRoots.Equal(x509.NewCertPool())) // check not empty
	})

	t.Run("happy path - multiple calls", func(t *testing.T) {
		// We need to test multiple calls to Roots(). because the first call
		// closes rootCertZipReader after which Roots() returns cached values.

		// given
		cp := internal.NewNitroCertProvider(
			internal.NewEmbeddedRootCertZipReader(),
		)

		// when
		_, err := cp.Roots()
		require.NoError(t, err)
		gotRoots, err := cp.Roots()

		// then
		require.NoError(t, err)
		assert.False(t, gotRoots.Equal(x509.NewCertPool())) // check not empty
	})

	t.Run("cannot read root certs", func(t *testing.T) {
		// given
		rc := mocks.NewIoReadCloser(t)
		cp := internal.NewNitroCertProvider(rc)

		// expecting
		rc.EXPECT().Read(mock.Anything).Return(0, assert.AnError)
		rc.EXPECT().Close().Return(nil)

		// when
		_, err := cp.Roots()

		// then
		assert.ErrorIs(t, err, assert.AnError)
		assert.ErrorContains(t, err, "reading ZIP bytes")
	})

	t.Run("digest mismatch", func(t *testing.T) {
		// given
		rc := mocks.NewIoReadCloser(t)
		cp := internal.NewNitroCertProvider(rc)

		// expecting
		rc.EXPECT().Read(mock.Anything).Return(0, io.EOF)
		rc.EXPECT().Close().Return(nil)

		// when
		_, err := cp.Roots()

		// then
		assert.ErrorContains(t, err, "digest mismatch")
	})

	t.Run("cannot unzip root certs", func(t *testing.T) {
		// given
		unzipRoots := mocks.NewInternalUnzipAWSRootCertsFunc(t)
		cp := internal.NewNitroCertProvider(
			internal.NewEmbeddedRootCertZipReader(),
		)
		cp.UnzipAWSRootCerts = unzipRoots.Execute

		// expecting
		unzipRoots.EXPECT().
			Execute(mock.Anything).
			Return(nil, assert.AnError)

		// when
		_, err := cp.Roots()

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
		t.Run("cannot append "+tt.name+" cert", func(t *testing.T) {
			// given
			unzipRoots := mocks.NewInternalUnzipAWSRootCertsFunc(t)
			cp := internal.NewNitroCertProvider(
				internal.NewEmbeddedRootCertZipReader(),
			)
			cp.UnzipAWSRootCerts = unzipRoots.Execute

			// expecting
			unzipRoots.EXPECT().
				Execute(mock.Anything).
				Return(tt.pemCert, nil)

			// when
			_, err := cp.Roots()

			// then
			assert.ErrorContains(t, err, "appending cert")
		})
	}
}

func TestSelfSignedCertProvider_Interfaces(t *testing.T) {
	var _ internal.CertProvider = internal.NewSelfSignedCertProvider()
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
