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
	fDocument = flag.String("attestation", "", "Attestation document in standard Base64 encoding")
)

func main() {
	flag.Parse()

	if "" == *fDocument {
		flag.PrintDefaults()
		os.Exit(1)
	}

	attestationBytes, err := base64.StdEncoding.DecodeString(*fDocument)
	if nil != err {
		fmt.Println(
			"Provided attestation is not encoded as a valid, " +
				"standard Base64 string",
		)
		os.Exit(2)
	}

	res, err := nitrite.Verify(
		attestationBytes,
		nitrite.NewNitroCertProvider(),
		nitrite.WithAttestationTime(),
	)

	resJSON := ""

	if nil != res {
		enc, err := json.Marshal(res.Document)
		if nil != err {
			panic(err)
		}

		resJSON = string(enc)
	}

	if nil != err {
		fmt.Printf("Attestation verification failed with error %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("%v\n", resJSON)
}
