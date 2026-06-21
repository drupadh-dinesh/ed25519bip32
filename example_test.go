package ed25519bip32_test

import (
	"crypto/ed25519"
	"fmt"

	"github.com/drupadh-dinesh/ed25519bip32"
)

func Example() {
	seed := make([]byte, 32)

	master, err := ed25519bip32.NewMaster(seed)
	if err != nil {
		panic(err)
	}

	acct, err := master.DerivePath("m/44'/0'/0'")
	if err != nil {
		panic(err)
	}

	msg := []byte("hello")
	sig := acct.Sign(msg)

	fmt.Println(ed25519.Verify(acct.PublicKey(), msg, sig))
	// Output: true
}
