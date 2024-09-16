package internal

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// Document represents the AWS Nitro Enclave Attestation Document.
type Document struct {
	ModuleID    string          `cbor:"module_id" json:"module_id"`
	Timestamp   uint64          `cbor:"timestamp" json:"timestamp"`
	Digest      string          `cbor:"digest" json:"digest"`
	PCRs        map[uint][]byte `cbor:"pcrs" json:"pcrs"`
	Certificate []byte          `cbor:"certificate" json:"certificate"`
	CABundle    [][]byte        `cbor:"cabundle" json:"cabundle"`

	PublicKey []byte `cbor:"public_key" json:"public_key,omitempty"`
	UserData  []byte `cbor:"user_data" json:"user_data,omitempty"`
	Nonce     []byte `cbor:"nonce" json:"nonce,omitempty"`
}

func (doc Document) CreatedAt() time.Time {
	if doc.Timestamp == 0 {
		return time.Time{}
	}

	// Pg. 64 of https://docs.aws.amazon.com/pdfs/enclaves/latest/user/enclaves-user.pdf
	// describes Timestamp as "UTC time when document was created, in milliseconds".
	// On the other, self-signed attestation timestamps are in seconds, so
	// we need to figure out which time of timestamp to convert.
	// TODO: Remove this check and use UnixMilli as part of
	//  https://blocky.atlassian.net/browse/BKY-5620

	var createdAt time.Time
	if time.UnixMilli(int64(doc.Timestamp)).Year() < 1980 {
		createdAt = time.Unix(int64(doc.Timestamp), 0)
	} else {
		createdAt = time.UnixMilli(int64(doc.Timestamp))
	}

	return createdAt
}

func (doc Document) Debug() (bool, error) {
	pcr0, ok := doc.PCRs[0]
	if !ok {
		return false, fmt.Errorf("PCR0 not found")
	}

	pcr0Int, err := strconv.Atoi(hex.EncodeToString(pcr0))

	debug := err == nil && pcr0Int == 0

	return debug, nil
}
