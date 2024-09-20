package internal

import (
	"crypto/x509"
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

func (doc Document) Verify(
	certProvider CertProvider,
	verificationTime VerificationTimeFunc,
) (*x509.Certificate, []*x509.Certificate, error) {
	err := doc.CheckMandatoryFields()
	if err != nil {
		return nil, nil, err
	}

	err = doc.CheckOptionalFields()
	if err != nil {
		return nil, nil, err
	}

	cert, certificates, err := doc.CheckCertificates(certProvider, verificationTime)
	if err != nil {
		return nil, nil, err
	}
	return cert, certificates, nil
}

func missingFieldError(field string) error {
	return fmt.Errorf("missing %s", field)
}

func (doc Document) CheckMandatoryFields() error {
	if doc.ModuleID == "" {
		return missingFieldError("module id")
	}
	if doc.Digest == "" {
		return missingFieldError("digest")
	}
	if doc.Timestamp < 1 {
		return missingFieldError("timestamp")
	}
	// TODO: Add PR comment asking if nil checks are needed since we use len later
	if doc.PCRs == nil {
		return missingFieldError("pcrs")
	}
	if doc.Certificate == nil {
		return missingFieldError("certificate")
	}
	if doc.Digest != "SHA384" {
		return fmt.Errorf("expected 'SHA384' digest but got '%s' digest", doc.Digest)
	}
	if len(doc.PCRs) < 1 || len(doc.PCRs) > 32 {
		return fmt.Errorf("expected 1 to 32 pcrs but got %v pcrs", len(doc.PCRs))
	}

	for key, value := range doc.PCRs {
		if key > 31 {
			return fmt.Errorf("pcr key '%v' is out of range [0, 31]", key)
		}

		if value == nil {
			return fmt.Errorf("pcr value for key '%v' is nil", key)
		}

		if !(32 == len(value) ||
			48 == len(value) ||
			64 == len(value) ||
			96 == len(value)) {
			return fmt.Errorf(
				"expected pcr len of 32, 48, 64, or 96 but got '%v'",
				len(value),
			)
		}
	}
	return nil
}

func (doc Document) CheckOptionalFields() error {
	if len(doc.PublicKey) > MaxPublicKeyLen {
		return fmt.Errorf(
			"max public key len is '%v' but got '%v'",
			MaxPublicKeyLen,
			len(doc.PublicKey),
		)
	}

	if len(doc.UserData) > MaxUserDataLen {
		return fmt.Errorf(
			"max user data len is '%v' but got '%v'",
			MaxUserDataLen,
			len(doc.UserData),
		)
	}

	if len(doc.Nonce) > MaxNonceLen {
		return fmt.Errorf(
			"max nonce len is '%v' but got '%v'",
			MaxNonceLen,
			len(doc.Nonce),
		)
	}
	return nil
}

func (doc Document) CheckCertificates(
	certProvider CertProvider,
	verificationTime VerificationTimeFunc,
) (*x509.Certificate, []*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(doc.Certificate)
	if nil != err {
		return nil, nil, fmt.Errorf("parsing cert: %w", err)
	}

	// TODO: remove the support for self-signed attestations as part of
	//  https://blocky.atlassian.net/browse/BKY-5620 (remove !cert.IsCA path)
	if !cert.IsCA && len(doc.CABundle) < 1 {
		return nil, nil, missingFieldError("cabundle")
	}

	if !cert.IsCA {
		for i, item := range doc.CABundle {
			if len(item) < 1 || len(item) > 1024 {
				return nil, nil, fmt.Errorf(
					"cabundle item '%v' expected len is [1, 1024] but got '%v'",
					i,
					len(item),
				)
			}
		}
	}

	if cert.PublicKeyAlgorithm != x509.ECDSA {
		return nil, nil, fmt.Errorf(
			"expected public key algo '%v' but got '%v'",
			x509.ECDSA,
			cert.PublicKeyAlgorithm,
		)
	}

	if cert.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		return nil, nil, fmt.Errorf(
			"expected signing algo '%v' but got '%v'",
			x509.ECDSAWithSHA384,
			cert.SignatureAlgorithm,
		)
	}

	var certificates []*x509.Certificate
	certificates = append(certificates, cert)

	intermediates := x509.NewCertPool()
	if !cert.IsCA {
		for i, item := range doc.CABundle {
			intermediate, err := x509.ParseCertificate(item)
			if nil != err {
				return nil, nil, fmt.Errorf(
					"parsing intermediate '%v' cert: %w",
					i,
					err,
				)
			}

			intermediates.AddCert(intermediate)
			certificates = append(certificates, intermediate)
		}
	}

	if verificationTime(doc).IsZero() {
		return nil, nil, fmt.Errorf("verification time is 0")
	}

	roots, err := certProvider.Roots()
	if nil != err {
		return nil, nil, fmt.Errorf("getting root certificates: %w", err)
	}

	_, err = cert.Verify(
		x509.VerifyOptions{
			Intermediates: intermediates,
			Roots:         roots,
			CurrentTime:   verificationTime(doc),
			KeyUsages: []x509.ExtKeyUsage{
				x509.ExtKeyUsageAny,
			},
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("verifying certificate: %w", err)
	}

	return cert, certificates, nil
}
