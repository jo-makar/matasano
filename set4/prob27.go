package main

import (
	"../set2/aes"
	"../set2/pkcs7"

	"bytes"
	"fmt"
	"log"
	"math/rand"
	"strconv"
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
	oracleIv := make([]byte, aes.BlockSize)
	copy(oracleIv, oracleKey)

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

	oracleValidate := func(input []byte) (bool, error) {
		padded, err := aes.CbcDecrypt(input, oracleKey, oracleIv)
		if err != nil {
			log.Panic(err)
		}

		plaintext, err := pkcs7.Unpad(padded, aes.BlockSize)
		if err != nil {
			log.Panic(err)
		}

		for _, c := range plaintext {
			if c > 0x7f {
				return false, fmt.Errorf("high ascii found: %v", plaintext)
			}
		}

		for _, t := range strings.Split(string(plaintext), ";") {
			u := strings.SplitN(t, "=", 2)
			if len(u) != 2 {
				continue
			}
			if u[0] == "admin" && u[1] == "true" {
				return true, nil
			}
		}
		return false, nil
	}

	//
	// Recover the key (by recovering the iv)
	//

	// Encrypt a single block message, call the plaintext p0 and the corresponding ciphertext c0.
	// Attempting to decrypt c0, <zero-block>, c0 will produce: p0, x0, p0 ^ iv
	// Where x0 is arbitrary and likely has high ascii, which will cause the validate oracle to display it.
	// Then the key (iv) can be recovered with the xor sum of of the first and third blocks: p0 ^ (p0 ^ iv) => iv

	ciphertext := oracleEncrypt("foo")
	c0 := ciphertext[0:aes.BlockSize]

	var buf bytes.Buffer
	buf.Write(c0)
	buf.Write(make([]byte, aes.BlockSize))
	buf.Write(c0)
	// Add the remaining blocks to ensure the PKCS padding is valid
	buf.Write(ciphertext[aes.BlockSize:len(ciphertext)])

	_, err := oracleValidate(buf.Bytes())
	if err == nil || !strings.HasPrefix(err.Error(), "high ascii found") {
		log.Panic("high ascii not found")
	}

	var recovered []byte
	errText := err.Error()
	for _, v := range strings.Split(errText[len("high ascii found: ["):len(errText)-1], " ") {
		n, err := strconv.Atoi(v)
		if err != nil {
			log.Panic(err)
		}
		recovered = append(recovered, byte(n))
	}
	if len(recovered) <= 3 * aes.BlockSize {
		log.Panic("insufficient recovered size")
	}

	recoveredKey := make([]byte, aes.BlockSize)
	for i := 0; i < aes.BlockSize; i++ {
		recoveredKey[i] = recovered[i] ^ recovered[i+2*aes.BlockSize]
	}

	if !bytes.Equal(recoveredKey, oracleKey) {
		log.Panic("recovered key incorrect")
	}
}
