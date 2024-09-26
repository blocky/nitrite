package internal

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

type SigningAlgorithm int

const (
	BadOrMissingAlgorithm SigningAlgorithm = iota
	ES384
)

// https://datatracker.ietf.org/doc/html/rfc8152#section-4.2
type CoseSign1 struct {
	_ struct{} `cbor:",toarray"`

	Protected   []byte
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

type CoseHeader struct {
	Alg interface{} `cbor:"1,keyasint,omitempty" json:"alg,omitempty"`
}

func MakeCoseSign1FromBytes(bytes []byte) (CoseSign1, error) {
	coseSign1 := CoseSign1{}
	err := cbor.Unmarshal(bytes, &coseSign1)
	if nil != err {
		return CoseSign1{}, fmt.Errorf("unmarshaling CoseSign1 from bytes: %w", err)
	}

	if len(coseSign1.Protected) == 0 {
		return CoseSign1{}, fmt.Errorf("missing cose protected headers")
	}

	if len(coseSign1.Payload) == 0 {
		return CoseSign1{}, fmt.Errorf("missing cose payload")
	}

	if len(coseSign1.Signature) == 0 {
		return CoseSign1{}, fmt.Errorf("missing cose signature")
	}
	return coseSign1, nil
}

func (c CoseSign1) CheckSignature(
	publicKey *ecdsa.PublicKey,
) ([]byte, error) {
	signingAlg, err := c.GetSigningAlgorithm()
	if err != nil {
		return nil, fmt.Errorf("extracting signing algorithm: %w", err)
	}

	// https://datatracker.ietf.org/doc/html/rfc8152#section-4.4
	sigStruct := struct {
		_ struct{} `cbor:",toarray"`

		Context     string
		Protected   []byte
		ExternalAAD []byte
		Payload     []byte
	}{
		Context:     "Signature1",
		Protected:   c.Protected,
		ExternalAAD: []byte{},
		Payload:     c.Payload,
	}

	sigStructBytes, err := cbor.Marshal(&sigStruct)
	if err != nil {
		return nil, fmt.Errorf("marshaling cose signature struct: %w", err)
	}

	var sigStructHash []byte
	switch signingAlg {
	case ES384:
		if publicKey.Curve.Params().Name != "P-384" {
			return nil, fmt.Errorf(
				"cose signing alg '%v' does not match public key signing alg '%s'",
				signingAlg,
				publicKey.Curve.Params().Name,
			)
		}

		h := sha512.Sum384(sigStructBytes)
		sigStructHash = h[:]
	default:
		return nil, fmt.Errorf("unsupported signing alg '%v'", signingAlg)
	}

	if len(c.Signature) != 2*len(sigStructHash) {
		return nil, fmt.Errorf(
			"expected signature len '%v' got '%v'",
			2*len(sigStructHash),
			len(c.Signature),
		)
	}

	r := big.NewInt(0)
	s := big.NewInt(0)
	r = r.SetBytes(c.Signature[:len(sigStructHash)])
	s = s.SetBytes(c.Signature[len(sigStructHash):])

	signatureOK := ecdsa.Verify(publicKey, sigStructHash, r, s)
	if !signatureOK {
		return nil, fmt.Errorf("failed to verify ecdsa signature")
	}
	return sigStructBytes, nil
}

func (c CoseSign1) GetSigningAlgorithm() (SigningAlgorithm, error) {
	header := CoseHeader{}
	err := cbor.Unmarshal(c.Protected, &header)
	if nil != err {
		return BadOrMissingAlgorithm,
			fmt.Errorf("unmarshaling cose protected header: %w", err)
	}

	intAlg, ok := header.AlgorithmInt()
	if ok {
		switch intAlg {
		case -35:
			return ES384, nil
		default:
			return BadOrMissingAlgorithm,
				fmt.Errorf("unsupported signing algorithm int '%v'", intAlg)
		}
	}

	strAlg, ok := header.AlgorithmString()
	if ok {
		switch strAlg {
		case "ES384":
			return ES384, nil
		default:
			return BadOrMissingAlgorithm,
				fmt.Errorf("unsupported signing algorithm string '%s'", strAlg)
		}
	}
	return BadOrMissingAlgorithm, fmt.Errorf("unsupported signing algorithm type")
}

func (h *CoseHeader) AlgorithmInt() (int64, bool) {
	switch h.Alg.(type) {
	case int64:
		return h.Alg.(int64), true
	}
	return 0, false
}

func (h *CoseHeader) AlgorithmString() (string, bool) {
	switch h.Alg.(type) {
	case string:
		return h.Alg.(string), true
	}
	return "", false
}
