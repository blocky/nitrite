package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/blocky/nitrite"
)

var (
	fAttestation = flag.String("attestation", "", "Attestation document in standard Base64 encoding")
	fAllowDebug  = flag.Bool("allowdebug", false, "Allow verification of attestation generated in debug mode")
)

func main() {
	flag.Parse()

	if *fAttestation == "" {
		bytes, err := io.ReadAll(os.Stdin)
		if err != nil {
			err = fmt.Errorf(
				"reading base64 attestation string from stdin: %w",
				err,
			)
			slog.Error(err.Error())
			os.Exit(2)
		}
		*fAttestation = string(bytes)
	}

	attestation, err := base64.StdEncoding.DecodeString(*fAttestation)
	if nil != err {
		err = fmt.Errorf("decoding attestation: %w", err)
		slog.Error(err.Error())
		os.Exit(2)
	}

	verifier, err := nitrite.New(nitrite.WithAllowDebug(*fAllowDebug))
	if err != nil {
		err = fmt.Errorf("creating verifier: %w", err)
		slog.Error(err.Error())
		os.Exit(2)
	}

	res, err := verifier.Verify(attestation)
	if err != nil {
		err = fmt.Errorf("verifying attestation: %w", err)
		slog.Error(err.Error())
		os.Exit(2)
	}

	enc, err := json.Marshal(res.Document)
	if err != nil {
		err = fmt.Errorf("marshalling attestation: %w", err)
		slog.Error(err.Error())
		os.Exit(2)
	}

	fmt.Printf("%v\n", string(enc))
}
