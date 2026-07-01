package hdwallet_test

import (
	"crypto/ed25519"
	"fmt"

	hdwallet "github.com/drupadh-dinesh/eddsa-hdwallet"
)

func Example() {
	seed := make([]byte, 32)

	master, err := hdwallet.NewMaster(seed)
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
