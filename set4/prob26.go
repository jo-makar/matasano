package main

import (
	"../set3/aes"

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
	oracleNonce := rand.Uint64()

	oracleEncrypt := func(input string) []byte {
		escape := func(s string) string {
			t := strings.ReplaceAll(s, ";", "%3B")
			return strings.ReplaceAll(t, "=", "%3D")
		}

		var plaintext bytes.Buffer
		plaintext.WriteString("comment1=cooking%20MCs;userdata=")
		plaintext.WriteString(escape(input))
		plaintext.WriteString(";comment2=%20like%20a%20pound%20of%20back")

		ciphertext, err := aes.CtrEncrypt(plaintext.Bytes(), oracleKey, oracleNonce)
		if err != nil {
			log.Panic(err)
		}
		return ciphertext
	}

	oracleValidate := func(input []byte) bool {
		plaintext, err := aes.CtrDecrypt(input, oracleKey, oracleNonce)
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

	// Set the target region to be zeros, then the ciphertext will be the encrypted keystream.
	// The encrypted keystream can be used to directly set the value of the target plaintext.

	desiredPlaintext := []byte("x;admin=true")
	ciphertext := oracleEncrypt(string(make([]byte, len(desiredPlaintext))))

	var modifiedCiphertext bytes.Buffer
	modifiedCiphertext.Write(ciphertext[0:len("comment1=cooking%20MCs;userdata=")])

	offset := modifiedCiphertext.Len()
	for i := 0; i < len(desiredPlaintext); i++ {
		modifiedCiphertext.WriteByte(desiredPlaintext[i] ^ ciphertext[offset + i])
	}

	offset += len(desiredPlaintext)
	modifiedCiphertext.Write(ciphertext[offset:offset+len(";comment2=%20like%20a%20pound%20of%20back")])

	if !oracleValidate(modifiedCiphertext.Bytes()) {
		log.Fatal(errors.New("admin not set"))
	}
}
