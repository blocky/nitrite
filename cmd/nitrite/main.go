package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/blocky/nitrite"
)

var (
	fAttestation = flag.String("attestation", "", "Attestation document in standard Base64 encoding")
	fDebug       = flag.Bool("debug", false, "Allow verification of attestation generated in debug mode")
)

// todo: test the params

func main() {
	flag.Parse()

	if "" == *fAttestation {
		flag.PrintDefaults()
		os.Exit(1)
	}

	attestation, err := base64.StdEncoding.DecodeString(*fAttestation)
	if nil != err {
		err = fmt.Errorf("decoding attestation: %w", err)
		slog.Error(err.Error())
		os.Exit(2)
	}

	verifier, err := nitrite.NewVerifier(nitrite.WithDebug(*fDebug))
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
