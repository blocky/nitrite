package cose

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"

	"github.com/blocky/nitrite/pkg/attestation"
	"github.com/fxamacker/cbor/v2"
)

const (
	ErrBadAttestationDocument         = "Bad attestation document"
	ErrBadCOSESign1Structure          = "Data is not a COSESign1 array"
	ErrBadSignature                   = "Payload's signature does not match signature from certificate"
	ErrCOSESign1EmptyProtectedSection = "COSESign1 protected section is nil or empty"
	ErrCOSESign1EmptyPayloadSection   = "COSESign1 payload section is nil or empty"
	ErrCOSESign1EmptySignatureSection = "COSESign1 signature section is nil or empty"
	ErrCOSESign1BadAlgorithm          = "COSESign1 algorithm not ECDSA384"
	ErrMarshallingCoseSignature       = "Could not marshal COSE signature"
)

type CoseHeader struct {
	Alg interface{} `cbor:"1,keyasint,omitempty" json:"alg,omitempty"`
}

type CosePayload struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

type CoseSignature struct {
	_           struct{} `cbor:",toarray"`
	Context     string
	Protected   []byte
	ExternalAAD []byte
	Payload     []byte
}

func ExtractCosePayload(
	data []byte,
) (CosePayload, error) {
	cose := CosePayload{}
	err := cbor.Unmarshal(data, &cose)
	if nil != err {
		return CosePayload{}, fmt.Errorf(
			"%s: %w",
			ErrBadCOSESign1Structure,
			err,
		)
	}
	return cose, nil
}

func VerifyCosePayload(
	cose CosePayload,
) error {
	if cose.Protected == nil || len(cose.Protected) == 0 {
		return errors.New(ErrCOSESign1EmptyProtectedSection)
	}

	if cose.Payload == nil || len(cose.Payload) == 0 {
		return errors.New(ErrCOSESign1EmptyPayloadSection)
	}

	if cose.Signature == nil || len(cose.Signature) == 0 {
		return errors.New(ErrCOSESign1EmptySignatureSection)
	}
	return nil
}

func ExtractCoseHeader(
	cose CosePayload,
) (CoseHeader, error) {
	header := CoseHeader{}
	err := cbor.Unmarshal(cose.Protected, &header)
	if nil != err {
		return CoseHeader{}, fmt.Errorf(
			"%s: %w",
			ErrBadCOSESign1Structure,
			err,
		)
	}
	return header, nil
}

func VerifyCoseHeader(
	header CoseHeader,
) error {
	// https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
	switch header.Alg.(type) {
	case int64:
		switch header.Alg.(int64) {
		case -35: // Number for ES384 - OK
			return nil
		default:
			return errors.New(ErrCOSESign1BadAlgorithm)
		}
	case string:
		switch header.Alg.(string) {
		case "ES384": // OK
			return nil
		default:
			return errors.New(ErrCOSESign1BadAlgorithm)
		}
	default:
		return errors.New(ErrCOSESign1BadAlgorithm)
	}
}

func VerifyCoseSign1(
	cosePayload CosePayload,
	cert *x509.Certificate,
) ([]byte, error) {
	coseSig := CoseSignature{
		Context:     "Signature1",
		Protected:   cosePayload.Protected,
		ExternalAAD: []byte{},
		Payload:     cosePayload.Payload,
	}
	sigStruct, err := cbor.Marshal(&coseSig)
	if err != nil {
		return nil, fmt.Errorf(
			"%s: %w",
			ErrMarshallingCoseSignature,
			err,
		)
	}

	signatureOk := CheckECDSASignature(
		cert.PublicKey.(*ecdsa.PublicKey),
		sigStruct,
		cosePayload.Signature,
	)
	if !signatureOk {
		return nil, errors.New(ErrBadSignature)

	}
	return sigStruct, nil
}

func CheckECDSASignature(
	publicKey *ecdsa.PublicKey,
	sigStruct, signature []byte,
) bool {
	// https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
	var hashSigStruct []byte
	switch publicKey.Curve.Params().Name {
	case "P-224":
		h := sha256.Sum224(sigStruct)
		hashSigStruct = h[:]
	case "P-256":
		h := sha256.Sum256(sigStruct)
		hashSigStruct = h[:]
	case "P-384":
		h := sha512.Sum384(sigStruct)
		hashSigStruct = h[:]
	case "P-512":
		h := sha512.Sum512(sigStruct)
		hashSigStruct = h[:]
	default:
		return false
	}

	if len(signature) != 2*len(hashSigStruct) {
		return false
	}

	r := big.NewInt(0)
	s := big.NewInt(0)
	r = r.SetBytes(signature[:len(hashSigStruct)])
	s = s.SetBytes(signature[len(hashSigStruct):])
	return ecdsa.Verify(publicKey, hashSigStruct, r, s)
}

func ExtractAttestationDoc(
	payload CosePayload,
) (attestation.Document, error) {
	doc := attestation.Document{}
	err := cbor.Unmarshal(payload.Payload, &doc)
	if nil != err {
		return attestation.Document{}, fmt.Errorf(
			"%s: %w",
			ErrBadAttestationDocument,
			err,
		)
	}
	return doc, nil
}
