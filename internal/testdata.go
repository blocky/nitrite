package internal

import (
	_ "embed"
	"time"
)

//go:embed testdata/nitro_attestation.b64
var NitroAttestationB64 string
var NitroAttestationTime = time.Date(2024, time.September, 7, 14, 37, 39, 545000000, time.UTC)

//go:embed testdata/nitro_attestation_debug.b64
var DebugNitroAttestationB64 string
var DebugNitroAttestationTime = time.Date(2024, time.September, 7, 14, 38, 6, 508000000, time.UTC)

// Deprecated: Remove SelfSignedAttestationB64 as a part of https://blocky.atlassian.net/browse/BKY-5620
//
//go:embed testdata/selfsigned_attestation.b64
var SelfSignedAttestationB64 string

// Deprecated: Remove SelfSignedAttestationTime as a part of https://blocky.atlassian.net/browse/BKY-5620
var SelfSignedAttestationTime = time.Date(2024, time.April, 17, 18, 51, 46, 0, time.UTC)
