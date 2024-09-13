package integration_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/blocky/nitrite/internal"
)

func TestFetchingNitroCertProvider_Roots(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		if testing.Short() {
			t.SkipNow()
		}

		// given
		cp := internal.NewFetchingNitroCertProvider()

		// when
		got, err := cp.Roots()

		// then
		require.NoError(t, err)
		assert.NotEmpty(t, got)
	})
}

// TestEmbeddedAndFetchedCertsEqual tests that the certs fetched from AWS
// and the certs embedded in the repository are the same. If they are not,
// it may be possible the AWS has updated the Nitro Enclaves root certs.
func TestEmbeddedAndFetchedCertsEqual(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		if testing.Short() {
			t.SkipNow()
		}

		// given
		embeddedCP := internal.NewNitroCertProvider()
		fetchingCP := internal.NewFetchingNitroCertProvider()

		// when
		gotEmbeddedRoots, err := embeddedCP.Roots()
		gotFetchedRoots, err2 := fetchingCP.Roots()

		// then
		require.NoError(t, err)
		require.NoError(t, err2)
		assert.True(t, gotEmbeddedRoots.Equal(gotFetchedRoots))
	})
}
