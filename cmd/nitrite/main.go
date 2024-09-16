package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/blocky/nitrite"
)

var (
	fAttestation = flag.String("attestation", "", "Attestation document in standard Base64 encoding")
)

func main() {
	flag.Parse()

	if "" == *fAttestation {
		flag.PrintDefaults()
		os.Exit(1)
	}

	attestation, err := base64.StdEncoding.DecodeString(*fAttestation)
	if nil != err {
		fmt.Println(
			"Provided attestation is not encoded as a valid, " +
				"standard Base64 string",
		)
		os.Exit(2)
	}

	verifier, err := nitrite.NewDefaultVerifier()
	if err != nil {
		fmt.Printf("Creating verifier: %v\n", err)
		os.Exit(2)
	}

	res, err := verifier.Verify(attestation)
	if err != nil {
		fmt.Printf("Verifying attestation: %v\n", err)
		os.Exit(2)
	}

	enc, err := json.Marshal(res.Document)
	if err != nil {
		fmt.Printf("Marshalling attestation: %v\n", err)
	}

	fmt.Printf("%v\n", string(enc))
}
