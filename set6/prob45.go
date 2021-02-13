package main

import (
	"./dsa"

	"log"
	"math/big"
)

func main() {
	//
	// g = 0 will cause r to be zero
	// and will cause it to be verified by any signature
	// (as v will always be zero also as a result of g = 0)
	//

	// Current implementation doesn't support g = 0 so skipping this demonstration

	//
	// g = p+1 will cause r to be one
	//

	_, k := dsa.KeyPair(1024, 160)
	_, pubkey := dsa.KeyPairParams(k.P, k.Q, new(big.Int).Add(k.P, big.NewInt(1)))

	z := big.NewInt(1)
	r := new(big.Int).Mod(dsa.Modexp(pubkey.Y, z, pubkey.P), pubkey.Q)
	s := new(big.Int).Mod(new(big.Int).Mul(r, dsa.Invmod(z, pubkey.Q)), pubkey.Q)
	magicSig := &dsa.Signature{ R: r, S: s }

	if !magicSig.Verify([]byte("Hello, world"), pubkey) {
		log.Printf("verify failed")
	}
	if !magicSig.Verify([]byte("Goodbyte, world"), pubkey) {
		log.Printf("verify failed")
	}
}
