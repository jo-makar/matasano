package main

import (
	"../set1/base64"
	"../set5/rsa"

	"bytes"
	"fmt"
	"log"
	"math/big"
)

func main() {
	privkey, pubkey := rsa.KeyPair(1024)

	oracleIsEven := func(ciphertext []byte) bool {
		plaintext := privkey.Decrypt(ciphertext)
		return plaintext[len(plaintext)-1] & 0x01 == 0
	}

	plaintext, err := base64.Decode("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")
	if err != nil {
		log.Panic(err)
	}
	ciphertext := pubkey.Encrypt(plaintext)

	lower, upper := big.NewInt(0), pubkey.N
	test := big.NewInt(2)

	for {
		if oracleIsEven(new(big.Int).Mul(new(big.Int).SetBytes(ciphertext),
		                                 new(big.Int).SetBytes(pubkey.Encrypt(test.Bytes()))).Bytes()) {

			upper = new(big.Int).Sub(upper,
			                         new(big.Int).Div(new(big.Int).Sub(upper, lower),
			                                          big.NewInt(2)))
		} else {
			lower = new(big.Int).Add(lower,
			                         new(big.Int).Div(new(big.Int).Sub(upper, lower),
			                                          big.NewInt(2)))
		}

		if upper.Cmp(new(big.Int).Add(lower, big.NewInt(1))) == 0 {
			fmt.Printf("\n")
			break
		}

		test.Mul(test, big.NewInt(2))

		fmt.Printf(".")
	}

	if bytes.Equal(pubkey.Encrypt(lower.Bytes()), ciphertext) {
		log.Printf("plaintext = %q", string(lower.Bytes()))
	} else if bytes.Equal(pubkey.Encrypt(upper.Bytes()), ciphertext) {
		log.Printf("plaintext = %q", string(upper.Bytes()))
	}
}
