package internal_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/blocky/nitrite/internal"
)

func TestDocument_CreatedAt(t *testing.T) {
	happyPathTests := []struct {
		name      string
		timestamp uint64
		wantTime  time.Time
	}{
		{
			"happy path",
			uint64(nitroAttestationTime.UnixMilli()),
			nitroAttestationTime,
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
		{"happy path - not in debug mode", map[uint][]byte{0: {0x01}}, false},
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

	t.Run("cannot parse PCR0", func(t *testing.T) {
		// given
		doc := internal.Document{PCRs: map[uint][]byte{0: {0xAB}}}

		// when
		_, err := doc.Debug()

		// then
		assert.ErrorContains(t, err, "parsing PCR0")
	})
}
