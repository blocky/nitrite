package main_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

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
	t.Run("nitro attestation", func(t *testing.T) {
		// given
		cmd := "go run main.go"
		cmd += " -attestation " + internal.NitroAttestationB64

		// when
		outDoc, err := runNitriteWithEnv(cmd, nil)

		// then
		require.NoError(t, err)
		assert.NotEmpty(t, outDoc)
	})

	t.Run("debug nitro attestation", func(t *testing.T) {
		// given
		cmd := "go run main.go"
		cmd += " -attestation " + internal.DebugNitroAttestationB64
		cmd += " -allowdebug"

		// when
		outDoc, err := runNitriteWithEnv(cmd, nil)

		// then
		require.NoError(t, err)
		assert.NotEmpty(t, outDoc)
	})

	t.Run("cannot verify debug nitro attestation without allowdebug", func(t *testing.T) {
		// given
		cmd := "go run main.go"
		cmd += " -attestation " + internal.DebugNitroAttestationB64

		// when
		_, err := runNitriteWithEnv(cmd, nil)

		// then
		assert.ErrorContains(t, err, "attestation was generated in debug mode")
	})

	t.Run("self-signed attestation", func(t *testing.T) {
		// given
		cmd := "go run main.go"
		cmd += " -attestation " + internal.SelfSignedAttestationB64
		cmd += " -allowselfsigned"

		// when
		outDoc, err := runNitriteWithEnv(cmd, nil)

		// then
		require.NoError(t, err)
		assert.NotEmpty(t, outDoc)
	})

	t.Run("cannot verify self-signed attestation", func(t *testing.T) {
		// given
		cmd := "go run main.go"
		cmd += " -attestation " + internal.SelfSignedAttestationB64

		// when
		_, err := runNitriteWithEnv(cmd, nil)

		// then
		assert.ErrorContains(t, err, "certificate signed by unknown authority")
	})
}
