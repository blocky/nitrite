package nitrite_error

type NitriteError string

func (n NitriteError) Error() string { return string(n) }

const (
	ErrBadCOSESign1Structure          = NitriteError("Data is not a COSESign1 array")
	ErrCOSESign1EmptyProtectedSection = NitriteError("COSESign1 protected section is nil or empty")
	ErrCOSESign1EmptyPayloadSection   = NitriteError("COSESign1 payload section is nil or empty")
	ErrCOSESign1EmptySignatureSection = NitriteError("COSESign1 signature section is nil or empty")
	ErrCOSESign1BadAlgorithm          = NitriteError("COSESign1 algorithm not ECDSA384")

	ErrBadAttestationDocument           = NitriteError("Bad attestation document")
	ErrMandatoryFieldsMissing           = NitriteError("One or more of mandatory fields missing")
	ErrBadDigest                        = NitriteError("Payload 'digest' is not SHA384")
	ErrBadTimestamp                     = NitriteError("Payload 'timestamp' is 0 or less")
	ErrBadPCRs                          = NitriteError("Payload 'pcrs' is less than 1 or more than 32")
	ErrBadPCRIndex                      = NitriteError("Payload 'pcrs' key index is not in [0, 32)")
	ErrBadPCRValue                      = NitriteError("Payload 'pcrs' value is nil or not of length {32,48,64}")
	ErrBadCABundle                      = NitriteError("Payload 'cabundle' has 0 elements")
	ErrBadCABundleItem                  = NitriteError("Payload 'cabundle' has a nil item or of length not in [1, 1024]")
	ErrBadPublicKey                     = NitriteError("Payload 'public_key' length greater than maxPublicKeyLen")
	ErrBadUserData                      = NitriteError("Payload 'user_data' length greater than maxUserDataLen")
	ErrBadNonce                         = NitriteError("Payload 'nonce' length greater than maxNonceLen")
	ErrBadCertificatePublicKeyAlgorithm = NitriteError("Payload 'certificate' has a bad public key algorithm (not ECDSA)")
	ErrBadCertificateSigningAlgorithm   = NitriteError("Payload 'certificate' has a bad public key signing algorithm (not ECDSAWithSHA384)")
	ErrBadSignature                     = NitriteError("Payload's signature does not match signature from certificate")
	ErrMarshallingCoseSignature         = NitriteError("Could not marshal COSE signature")
)
