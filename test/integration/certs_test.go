package integration_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/blocky/nitrite/internal"
)

func TestEmbeddedAndFetchedCertsEqual(t *testing.T) {
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
}
