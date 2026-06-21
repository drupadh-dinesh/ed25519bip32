package ed25519bip32

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
)

var (
	versionPrivate = [4]byte{0x0e, 0xd2, 0x55, 0x19}
	versionPublic  = [4]byte{0x0e, 0xd2, 0x55, 0x1a}
)

const (
	serializedPublicPayloadLen  = 78
	serializedPrivatePayloadLen = 110
	base58Alphabet              = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	privateStringPrefix         = "edprv"
	publicStringPrefix          = "edpub"
)

// String serializes k as a Base58Check edprv or edpub extended key.
func (k *ExtendedKey) String() string {
	if k == nil || (k.isPrivate && len(k.key) != privateKeySize) || (!k.isPrivate && len(k.key) != publicKeySize) {
		return ""
	}
	payload := k.serialize()
	if k.isPrivate {
		return privateStringPrefix + base58CheckEncode(payload)
	}
	return publicStringPrefix + base58CheckEncode(payload)
}

// ParseExtendedKey parses a Base58Check edprv or edpub extended key.
func ParseExtendedKey(s string) (*ExtendedKey, error) {
	var encoded string
	switch {
	case strings.HasPrefix(s, privateStringPrefix):
		encoded = strings.TrimPrefix(s, privateStringPrefix)
	case strings.HasPrefix(s, publicStringPrefix):
		encoded = strings.TrimPrefix(s, publicStringPrefix)
	default:
		return nil, fmt.Errorf("%w: expected edprv or edpub prefix", ErrInvalidSerialization)
	}

	payload, err := base58CheckDecode(encoded)
	if err != nil {
		return nil, err
	}
	if len(payload) < 4 {
		return nil, fmt.Errorf("%w: payload length %d", ErrInvalidSerialization, len(payload))
	}
	var version [4]byte
	copy(version[:], payload[:4])

	var isPrivate bool
	switch version {
	case versionPrivate:
		isPrivate = true
		if len(payload) != serializedPrivatePayloadLen {
			return nil, fmt.Errorf("%w: private payload length %d", ErrInvalidSerialization, len(payload))
		}
	case versionPublic:
		isPrivate = false
		if len(payload) != serializedPublicPayloadLen {
			return nil, fmt.Errorf("%w: public payload length %d", ErrInvalidSerialization, len(payload))
		}
	default:
		return nil, fmt.Errorf("%w: unknown version %x", ErrInvalidSerialization, version)
	}

	keyMaterial := payload[45:]
	expectedKeyMaterialLen := 1 + publicKeySize
	if isPrivate {
		expectedKeyMaterialLen = 1 + privateKeySize
	}
	if len(keyMaterial) != expectedKeyMaterialLen {
		return nil, fmt.Errorf("%w: key material length %d", ErrInvalidSerialization, len(keyMaterial))
	}
	if isPrivate && keyMaterial[0] != 0x00 {
		return nil, fmt.Errorf("%w: private key marker missing", ErrInvalidSerialization)
	}
	if !isPrivate && keyMaterial[0] != 0x00 {
		return nil, fmt.Errorf("%w: public key marker missing", ErrInvalidSerialization)
	}

	var chainCode [32]byte
	copy(chainCode[:], payload[13:45])

	var parentFP [4]byte
	copy(parentFP[:], payload[5:9])

	return &ExtendedKey{
		key:       cloneBytes(keyMaterial[1:]),
		chainCode: chainCode,
		depth:     payload[4],
		parentFP:  parentFP,
		childNum:  binary.BigEndian.Uint32(payload[9:13]),
		isPrivate: isPrivate,
	}, nil
}

func (k *ExtendedKey) serialize() []byte {
	payloadLen := serializedPublicPayloadLen
	if k.isPrivate {
		payloadLen = serializedPrivatePayloadLen
	}
	payload := make([]byte, payloadLen)
	if k.isPrivate {
		copy(payload[:4], versionPrivate[:])
	} else {
		copy(payload[:4], versionPublic[:])
	}
	payload[4] = k.depth
	copy(payload[5:9], k.parentFP[:])
	binary.BigEndian.PutUint32(payload[9:13], k.childNum)
	copy(payload[13:45], k.chainCode[:])
	payload[45] = 0
	if k.isPrivate {
		copy(payload[46:], k.key)
	} else {
		copy(payload[46:], k.PublicKey())
	}
	return payload
}

func base58CheckEncode(payload []byte) string {
	checksum := checksum(payload)
	raw := make([]byte, 0, len(payload)+4)
	raw = append(raw, payload...)
	raw = append(raw, checksum[:]...)
	defer zero(raw)
	return base58Encode(raw)
}

func base58CheckDecode(s string) ([]byte, error) {
	raw, err := base58Decode(s)
	if err != nil {
		return nil, err
	}
	if len(raw) < 4 {
		return nil, ErrInvalidSerialization
	}
	payload := raw[:len(raw)-4]
	got := raw[len(raw)-4:]
	want := checksum(payload)
	if !bytes.Equal(got, want[:]) {
		return nil, ErrChecksumMismatch
	}
	return cloneBytes(payload), nil
}

func checksum(payload []byte) [4]byte {
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	var out [4]byte
	copy(out[:], second[:4])
	return out
}

func base58Encode(src []byte) string {
	x := new(big.Int).SetBytes(src)
	base := big.NewInt(58)
	zeroInt := big.NewInt(0)
	mod := new(big.Int)

	var encoded []byte
	for x.Cmp(zeroInt) > 0 {
		x.DivMod(x, base, mod)
		encoded = append(encoded, base58Alphabet[mod.Int64()])
	}
	for _, b := range src {
		if b != 0 {
			break
		}
		encoded = append(encoded, base58Alphabet[0])
	}
	for left, right := 0, len(encoded)-1; left < right; left, right = left+1, right-1 {
		encoded[left], encoded[right] = encoded[right], encoded[left]
	}
	return string(encoded)
}

func base58Decode(s string) ([]byte, error) {
	if s == "" {
		return nil, ErrInvalidSerialization
	}

	result := big.NewInt(0)
	base := big.NewInt(58)
	for _, r := range s {
		index := bytes.IndexByte([]byte(base58Alphabet), byte(r))
		if r > 127 || index < 0 {
			return nil, fmt.Errorf("%w: invalid base58 character %q", ErrInvalidSerialization, r)
		}
		result.Mul(result, base)
		result.Add(result, big.NewInt(int64(index)))
	}

	decoded := result.Bytes()
	leadingZeroes := 0
	for leadingZeroes < len(s) && s[leadingZeroes] == base58Alphabet[0] {
		leadingZeroes++
	}
	out := make([]byte, leadingZeroes+len(decoded))
	copy(out[leadingZeroes:], decoded)
	return out, nil
}
