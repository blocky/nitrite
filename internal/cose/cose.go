package cose

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"math/big"

	"github.com/blocky/nitrite/internal/attestation"
	"github.com/blocky/nitrite/pkg/nitrite_error"
	"github.com/fxamacker/cbor/v2"
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

func (h *CoseHeader) AlgorithmString() (string, bool) {
	switch h.Alg.(type) {
	case string:
		return h.Alg.(string), true
	}
	return "", false
}

func (h *CoseHeader) AlgorithmInt() (int64, bool) {
	switch h.Alg.(type) {
	case int64:
		return h.Alg.(int64), true
	}
	return 0, false
}

func ExtractCosePayload(
	data []byte,
) (CosePayload, error) {
	cose := CosePayload{}
	err := cbor.Unmarshal(data, &cose)
	if nil != err {
		return CosePayload{}, nitrite_error.ErrBadCOSESign1Structure
	}
	return cose, nil
}

func VerifyCosePayload(
	cose CosePayload,
) error {
	if cose.Protected == nil || len(cose.Protected) == 0 {
		return nitrite_error.ErrCOSESign1EmptyProtectedSection
	}

	if cose.Payload == nil || len(cose.Payload) == 0 {
		return nitrite_error.ErrCOSESign1EmptyPayloadSection
	}

	if cose.Signature == nil || len(cose.Signature) == 0 {
		return nitrite_error.ErrCOSESign1EmptySignatureSection
	}
	return nil
}

func ExtractCoseHeader(
	cose CosePayload,
) (CoseHeader, error) {
	header := CoseHeader{}
	err := cbor.Unmarshal(cose.Protected, &header)
	if nil != err {
		return CoseHeader{}, nitrite_error.ErrBadCOSESign1Structure
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
			return nitrite_error.ErrCOSESign1BadAlgorithm
		}
	case string:
		switch header.Alg.(string) {
		case "ES384": // OK
			return nil
		default:
			return nitrite_error.ErrCOSESign1BadAlgorithm
		}
	default:
		return nitrite_error.ErrCOSESign1BadAlgorithm
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
		return nil, nitrite_error.ErrMarshallingCoseSignature
	}

	signatureOk := CheckECDSASignature(
		cert.PublicKey.(*ecdsa.PublicKey),
		sigStruct,
		cosePayload.Signature,
	)
	if !signatureOk {
		return nil, nitrite_error.ErrBadSignature
	}
	return sigStruct, nil
}

func CheckECDSASignature(
	publicKey *ecdsa.PublicKey,
	sigStruct, signature []byte,
) bool {
	// https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
	var hashSigStruct []byte = nil
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
		return attestation.Document{}, nitrite_error.ErrBadAttestationDocument
	}
	return doc, nil
}
