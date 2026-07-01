// Package eddsa-hdwallet implements hierarchical deterministic (HD) wallets for
// Ed25519 using the Ed25519-BIP32 derivation scheme.
//
// The package supports:
//
//   - Master key generation from a seed
//   - Hardened and non-hardened child derivation
//   - Public extended keys and watch-only derivation
//   - BIP32-style derivation paths
//   - Ed25519 signing
//   - Extended key serialization and parsing
//
// A master key is created from a seed:
//
//	seed := make([]byte, 32)
//	master, err := eddsa-hdwallet.NewMaster(seed)
//
// Child keys can be derived directly:
//
//	child, err := master.Derive(eddsa-hdwallet.Hardened(0))
//
// Or using a derivation path:
//
//	account, err := master.DerivePath("m/44'/1815'/0'/0/0")
//
// Public extended keys may be obtained using Neuter:
//
//	xpub := account.Neuter()
//
// Public extended keys can derive only non-hardened children.
//
// Messages can be signed using private extended keys:
//
//	sig := account.Sign(message)
//
// Extended keys can be serialized and restored:
//
//	encoded := account.String()
//	parsed, err := eddsa-hdwallet.ParseExtendedKey(encoded)
//
// The implementation follows the Ed25519-BIP32 model and produces
// deterministic key hierarchies suitable for wallet applications.
package hdwallet
