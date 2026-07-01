package hdwallet

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/subtle"

	"filippo.io/edwards25519"
)

const (
	masterKeySalt       = "ed25519-bip32 seed"
	masterChainCodeSalt = "ed25519-bip32 chain code"
	scalarSize          = 32
	prefixSize          = 32
	publicKeySize       = ed25519.PublicKeySize
	privateKeySize      = scalarSize + prefixSize

	minSeedBytes = 16
	maxSeedBytes = 64
)

// ExtendedKey is an Ed25519-BIP32 extended key.
//
// For private extended keys, key contains 64 bytes: a 32-byte little-endian
// private scalar followed by a 32-byte Ed25519 nonce prefix. For public
// extended keys returned by Neuter or parsed from edpub strings, key contains
// the 32-byte Ed25519 public key. All methods copy returned key material.
type ExtendedKey struct {
	key       []byte
	chainCode [32]byte

	depth    uint8
	childNum uint32
	parentFP [4]byte

	isPrivate bool
}

// NewMaster creates an Ed25519-BIP32 master extended private key from seed.
func NewMaster(seed []byte) (*ExtendedKey, error) {
	if len(seed) < minSeedBytes || len(seed) > maxSeedBytes {
		return nil, ErrInvalidSeed
	}

	mac := hmac.New(sha512.New, []byte(masterKeySalt))
	_, _ = mac.Write(seed)
	sum := mac.Sum(nil)
	defer zero(sum)

	key := make([]byte, privateKeySize)
	copy(key, sum[:privateKeySize])
	pruneScalar(key[:scalarSize])

	var chainCode [32]byte
	chainMAC := hmac.New(sha512.New, []byte(masterChainCodeSalt))
	_, _ = chainMAC.Write(seed)
	chainMaterial := chainMAC.Sum(nil)
	defer zero(chainMaterial)
	copy(chainCode[:], chainMaterial[:32])

	return &ExtendedKey{
		key:       key,
		chainCode: chainCode,
		isPrivate: true,
	}, nil
}

// PublicKey returns a copy of the Ed25519 public key.
func (k *ExtendedKey) PublicKey() ed25519.PublicKey {
	if k == nil {
		return nil
	}
	if !k.isPrivate {
		if len(k.key) != publicKeySize {
			return nil
		}
		return cloneBytes(k.key)
	}
	if len(k.key) != privateKeySize {
		return nil
	}
	point := new(edwards25519.Point).ScalarBaseMult(scalarFromBytes(k.key[:scalarSize]))
	return cloneBytes(point.Bytes())
}

// PrivateKey returns a copy of the 64-byte Ed25519-BIP32 extended private key.
func (k *ExtendedKey) PrivateKey() ed25519.PrivateKey {
	if k == nil || !k.isPrivate || len(k.key) != privateKeySize {
		return nil
	}
	return cloneBytes(k.key)
}

// Sign signs msg with k's Ed25519 private key. It returns nil for public keys.
func (k *ExtendedKey) Sign(msg []byte) []byte {
	if k == nil || !k.isPrivate || len(k.key) != privateKeySize {
		return nil
	}
	publicKey := k.PublicKey()
	if len(publicKey) != publicKeySize {
		return nil
	}

	digest := sha512.Sum512(append(cloneBytes(k.key[scalarSize:privateKeySize]), msg...))
	r, err := edwards25519.NewScalar().SetUniformBytes(digest[:])
	if err != nil {
		return nil
	}
	rPoint := new(edwards25519.Point).ScalarBaseMult(r)
	encodedR := rPoint.Bytes()

	hramInput := make([]byte, 0, len(encodedR)+len(publicKey)+len(msg))
	hramInput = append(hramInput, encodedR...)
	hramInput = append(hramInput, publicKey...)
	hramInput = append(hramInput, msg...)
	hramDigest := sha512.Sum512(hramInput)
	hram, err := edwards25519.NewScalar().SetUniformBytes(hramDigest[:])
	if err != nil {
		return nil
	}

	privateScalar := scalarFromBytes(k.key[:scalarSize])
	s := edwards25519.NewScalar().MultiplyAdd(hram, privateScalar, r)

	signature := make([]byte, ed25519.SignatureSize)
	copy(signature[:32], encodedR)
	copy(signature[32:], s.Bytes())
	zero(hramInput)
	return signature
}

// Neuter returns the matching public extended key.
func (k *ExtendedKey) Neuter() *ExtendedKey {
	if k == nil {
		return nil
	}
	pub := k.PublicKey()
	if pub == nil {
		return nil
	}
	return &ExtendedKey{
		key:       pub,
		chainCode: k.chainCode,
		depth:     k.depth,
		childNum:  k.childNum,
		parentFP:  k.parentFP,
	}
}

// IsPrivate reports whether k contains private key material.
func (k *ExtendedKey) IsPrivate() bool {
	return k != nil && k.isPrivate
}

func (k *ExtendedKey) seed() []byte {
	if k == nil || !k.isPrivate || len(k.key) != privateKeySize {
		return nil
	}
	return k.key
}

func scalarFromBytes(b []byte) *edwards25519.Scalar {
	s, err := edwards25519.NewScalar().SetCanonicalBytes(b)
	if err == nil {
		return s
	}
	s, _ = edwards25519.NewScalar().SetBytesWithClamping(b)
	return s
}

func pruneScalar(k []byte) {
	k[0] &= 248
	k[31] &= 31
	k[31] |= 64
}

func cloneBytes(src []byte) []byte {
	if src == nil {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func zero(b []byte) {
	_ = subtle.XORBytes(b, b, b)
}
