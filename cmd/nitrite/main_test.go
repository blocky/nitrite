package main_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ionrock/procs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/blocky/nitrite"
	"github.com/blocky/nitrite/internal"
)

func runNitriteWithEnv(
	cmd string,
	env map[string]string,
) (nitrite.Document, error) {
	nitriteProc := procs.NewProcess(cmd)
	nitriteProc.OutputHandler = func(line string) string { return line }
	nitriteProc.ErrHandler = func(line string) string { return line }
	nitriteProc.Env = procs.ParseEnv(os.Environ())
	for k, v := range env {
		nitriteProc.Env[k] = v
	}

	err := nitriteProc.Start()
	if err != nil {
		return nitrite.Document{},
			fmt.Errorf("starting nitrite process: %w", err)
	}

	err = nitriteProc.Wait()
	if err != nil {
		errOut, errOutErr := nitriteProc.ErrOutput()
		err = errors.Join(err, errOutErr)
		return nitrite.Document{},
			fmt.Errorf("waiting on nitrite process '%s': %w", errOut, err)
	}

	outBytes, err := nitriteProc.Output()
	if err != nil {
		return nitrite.Document{},
			fmt.Errorf("getting nitrite process output: %w", err)
	}

	output := nitrite.Document{}
	err = json.Unmarshal(outBytes, &output)
	if err != nil {
		return nitrite.Document{},
			fmt.Errorf("unmarshaling nitrite process output: %w", err)
	}
	return output, nil
}

func TestExec(t *testing.T) {
	// TODO: Remove the self-signed attestation test case as a part of
	//  https://blocky.atlassian.net/browse/BKY-5620
	happyPathTests := []struct {
		name        string
		attestation string
		debug       bool
		selfSigned  bool
		time        time.Time
		wantPCR0    string
	}{
		{
			name:        "happy path - nitro",
			attestation: internal.NitroAttestationB64,
			debug:       false,
			selfSigned:  false,
			time:        internal.NitroAttestationTime,
			wantPCR0:    "5ypGyoCiYPsEShJUQvDH4zGBO8uvlyTZ84V3WJknZvLWVxCieqlK45Sd1U58n+hq",
		},
		{
			name:        "happy path - debug nitro",
			attestation: internal.DebugNitroAttestationB64,
			debug:       true,
			selfSigned:  false,
			time:        internal.DebugNitroAttestationTime,
			wantPCR0:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		{
			name:        "happy path - self signed",
			attestation: internal.SelfSignedAttestationB64,
			debug:       false,
			selfSigned:  true,
			time:        internal.SelfSignedAttestationTime,
			wantPCR0:    "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw",
		},
	}
	for _, tt := range happyPathTests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			cmd := "go run main.go"
			cmd += " -attestation " + tt.attestation
			if tt.debug {
				cmd += " -allowdebug"
			}
			if tt.selfSigned {
				cmd += " -allowselfsigned"
			}

			// when
			outDoc, err := runNitriteWithEnv(cmd, nil)

			// then
			require.NoError(t, err)
			assert.Equal(t, tt.time, outDoc.CreatedAt().UTC())
			assert.Equal(t, tt.wantPCR0, base64.StdEncoding.EncodeToString(outDoc.PCRs[0]))
			gotDebug, err := outDoc.Debug()
			require.NoError(t, err)
			assert.Equal(t, tt.debug, gotDebug)
		})
	}

	t.Run("cannot verify debug nitro attestation without allowdebug", func(t *testing.T) {
		// given
		cmd := "go run main.go"
		cmd += " -attestation " + internal.DebugNitroAttestationB64

		// when
		_, err := runNitriteWithEnv(cmd, nil)

		// then
		assert.ErrorContains(t, err, "attestation was generated in debug mode")
	})

	// TODO: As a part of https://blocky.atlassian.net/browse/BKY-5620,
	//  we are removing the self-signed attestation test case. Consider keeping
	//  this test case and removing this comment only.

	t.Run("cannot verify self-signed attestation without allowselfsigned", func(t *testing.T) {
		// given
		cmd := "go run main.go"
		cmd += " -attestation " + internal.SelfSignedAttestationB64

		// when
		_, err := runNitriteWithEnv(cmd, nil)

		// then
		assert.ErrorContains(t, err, "certificate signed by unknown authority")
	})
}
