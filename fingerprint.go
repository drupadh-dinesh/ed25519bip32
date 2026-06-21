package ed25519bip32

import "crypto/sha256"

// Fingerprint returns the first four bytes of HASH160-like key identifier.
//
// SLIP-0010 test vectors define the fingerprint as the first four bytes of
// RIPEMD160(SHA256(serP(publicKey))). This package uses that same layout with
// Ed25519 serP encoded as 0x00 || RFC8032 public key bytes.
func (k *ExtendedKey) Fingerprint() [4]byte {
	var out [4]byte
	pub := k.PublicKey()
	if len(pub) != publicKeySize {
		return out
	}

	serialized := make([]byte, 1+publicKeySize)
	serialized[0] = 0
	copy(serialized[1:], pub)
	sha := sha256.Sum256(serialized)
	ripe := ripemd160(sha[:])
	copy(out[:], ripe[:4])
	zero(serialized)
	return out
}
