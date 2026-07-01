package hdwallet

import "errors"

var (
	ErrInvalidSeed          = errors.New("eddsa-hdwallet: seed length must be between 16 and 64 bytes")
	ErrNilKey               = errors.New("eddsa-hdwallet: extended key is nil")
	ErrHardenedPublicChild  = errors.New("eddsa-hdwallet: cannot derive a hardened child from a public extended key")
	ErrDepthOverflow        = errors.New("eddsa-hdwallet: maximum derivation depth exceeded")
	ErrInvalidPath          = errors.New("eddsa-hdwallet: invalid derivation path")
	ErrInvalidSerialization = errors.New("eddsa-hdwallet: invalid extended key serialization")
	ErrChecksumMismatch     = errors.New("eddsa-hdwallet: extended key checksum mismatch")
	ErrInvalidKey           = errors.New("eddsa-hdwallet: invalid extended key")
)
