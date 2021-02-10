package main

import (
	"./rsa"

	"log"
	"math/big"
)

func main() {
	plaintext := []byte("attack at dawn")

	pubkeys := make([]*rsa.PubKey, 3)
	ciphertexts := make([]*big.Int, 3)
	for i := 0; i < 3; i++ {
		_, pubkey := rsa.KeyPair(256)
		ciphertext := pubkey.Encrypt(plaintext)

		pubkeys[i] = pubkey
		ciphertexts[i] = new(big.Int).SetBytes(ciphertext)
	}

	//
	// Apply the Chinese Remainder Theorem
	//

	// Given x % n1 = a1
	//             ...
	//       x % nk = ak
	// with n1, ..., nk being pairwise coprimes
	//
	// Then x = sum(a1 * N/ni * invmod(N/ni, ni)) % N
	// where N = n1 * ... * nk

	// Verify pubkey n values are pairwise coprimes
	for i := 0; i < 2; i++ {
		for j := i+1; j < 3; j++ {
			if !rsa.Coprime(pubkeys[i].N, pubkeys[j].N) {
				log.Panic("pubkey n pair not coprimes")
			}
		}
	}

	result := big.NewInt(0)

	for i := 0; i < 3; i++ {
		Ni := big.NewInt(1) // N / ni
		for j := 0; j < 3; j++ {
			if j != i {
				Ni.Mul(Ni, pubkeys[j].N)
			}
		}

		result.Add(result, new(big.Int).Mul(new(big.Int).Mul(ciphertexts[i], Ni),
		                                    rsa.Invmod(Ni, pubkeys[i].N)))
	}

	N := big.NewInt(1)
	for i := 0; i < 3; i++ {
		N.Mul(N, pubkeys[i].N)
	}

	result.Mod(result, N)

	// The math/big.Int type does not have a cube root function so show equivalence by cubing the plaintext
	if result.Cmp(new(big.Int).Exp(new(big.Int).SetBytes(plaintext), big.NewInt(3), nil)) != 0 {
		log.Panic("result != plaintext")
	}
}
