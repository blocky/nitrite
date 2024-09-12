package internal_test

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/blocky/nitrite"
	"github.com/blocky/nitrite/internal"
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
		{"invalid", []byte("invalid PEM bytes")},
		{"nil", nil},
	}
	for _, tt := range errorTests {
		t.Run("cannot append "+tt.name+" cert", func(t *testing.T) {
			// given
			cp := internal.NewNitroCertProvider()

			// when
			_, err := cp.RootsWithCerts(tt.derCert)

			// then
			assert.ErrorContains(t, err, "appending cert")
		})
	}
}

func TestFetchingNitroCertProvider_Interfaces(t *testing.T) {
	var _ nitrite.CertProvider = internal.NewFetchingNitroCertProvider()
}

func TestFetchingNitroCertProvider_Roots(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		// given
		cp := internal.NewFetchingNitroCertProvider()

		// when
		gotRoots, err := cp.Roots()

		// then
		require.NoError(t, err)
		assert.False(t, gotRoots.Equal(x509.NewCertPool())) // check not empty
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
