package ed25519bip32

import "testing"

func BenchmarkNewMaster(b *testing.B) {
	seed := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		_, err := NewMaster(seed)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDerivePath(b *testing.B) {
	master, err := NewMaster(make([]byte, 32))
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		_, err := master.DerivePath("m/44'/0'/0'")
		if err != nil {
			b.Fatal(err)
		}
	}
}
