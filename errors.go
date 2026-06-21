package ed25519bip32

import "errors"

var (
	ErrInvalidSeed          = errors.New("ed25519bip32: seed length must be between 16 and 64 bytes")
	ErrNilKey               = errors.New("ed25519bip32: extended key is nil")
	ErrHardenedPublicChild  = errors.New("ed25519bip32: cannot derive a hardened child from a public extended key")
	ErrDepthOverflow        = errors.New("ed25519bip32: maximum derivation depth exceeded")
	ErrInvalidPath          = errors.New("ed25519bip32: invalid derivation path")
	ErrInvalidSerialization = errors.New("ed25519bip32: invalid extended key serialization")
	ErrChecksumMismatch     = errors.New("ed25519bip32: extended key checksum mismatch")
	ErrInvalidKey           = errors.New("ed25519bip32: invalid extended key")
)
