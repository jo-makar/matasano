package main

import (
	"./aes"
	"./pkcs7"

	"bytes"
	"errors"
	"log"
	"math/rand"
	"strings"
	"time"
)

func main() {
	//
	// Define the oracle functions
 	//

	rand.Seed(time.Now().UnixNano())
	randBytes := func(n uint) []byte {
		b := make([]byte, n)
		rand.Read(b)
		return b
	}

	oracleKey := randBytes(aes.BlockSize)
	oracleIv := randBytes(aes.BlockSize)

	oracleEncrypt := func(input string) []byte {
		escape := func(s string) string {
			t := strings.ReplaceAll(s, ";", "%3B")
			return strings.ReplaceAll(t, "=", "%3D")
		}

		var plaintext bytes.Buffer
		plaintext.WriteString("comment1=cooking%20MCs;userdata=")
		plaintext.WriteString(escape(input))
		plaintext.WriteString(";comment2=%20like%20a%20pound%20of%20back")

		padded, err := pkcs7.Pad(plaintext.Bytes(), aes.BlockSize)
		if err != nil {
			log.Panic(err)
		}

		ciphertext, err := aes.CbcEncrypt(padded, oracleKey, oracleIv)
		if err != nil {
			log.Panic(err)
		}
		return ciphertext
	}

	oracleValidate := func(input []byte) bool {
		padded, err := aes.CbcDecrypt(input, oracleKey, oracleIv)
		if err != nil {
			log.Panic(err)
		}

		plaintext, err := pkcs7.Unpad(padded, aes.BlockSize)
		if err != nil {
			log.Panic(err)
		}

		//log.Printf("%q", string(plaintext))
		for _, t := range strings.Split(string(plaintext), ";") {
			u := strings.SplitN(t, "=", 2)
			if len(u) != 2 {
				continue
			}
			if u[0] == "admin" && u[1] == "true" {
				return true
			}
		}
		return false
	}

	//
	// Modify the ciphertext to edit the decrypted plaintext
 	//

 	// The prefixed string ends on a block boundary (32 bytes).
 	// Modify the second ciphertext block to make changes in the third plaintext block.
 	// Specifically arrange for it to become "x;admin=true<postfix>".

	// Using a plaintext block (or portion) of zeros means the ciphertext block (or portion)
	// will become the preceding ciphertext block encrypted.
	// This allows edits in the preceding ciphertext block to be reflected during decryption.
	// Ref: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
	
 	ciphertext := oracleEncrypt(string(make([]byte, 12)))

 	block := ciphertext[16:32]
 	target := []byte("x;admin=true")
 	for i := 0; i < len(target); i++ {
	 	block[i] ^= target[i]
 	}

 	modifiedCiphertext := make([]byte, len(ciphertext))
 	copy(modifiedCiphertext[0:16], ciphertext[0:16])
 	copy(modifiedCiphertext[16:32], block)
 	copy(modifiedCiphertext[32:], ciphertext[32:])

 	if !oracleValidate(modifiedCiphertext) {
	 	log.Fatal(errors.New("admin not set"))
 	}
}
