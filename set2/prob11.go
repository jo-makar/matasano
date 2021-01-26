package main

import (
	"./aes"
	"./pkcs7"

	"bytes"
	"errors"
	"log"
	"math/rand"
	"time"
)

func main() {
	//
	// Define the oracle function
	//

	rand.Seed(time.Now().UnixNano())

	oracle := func(input []byte) []byte {
		randBytes := func(n uint) []byte {
			b := make([]byte, n)
			rand.Read(b)
			return b
		}

		//
		// Preprocess the input:
		// Pre and post pad and pkcs7 pad
		//

		var plaintext bytes.Buffer
		plaintext.Write(randBytes(uint(5 + rand.Intn(6))))
		plaintext.Write(input)
		plaintext.Write(randBytes(uint(5 + rand.Intn(6))))

		padded, err := pkcs7.Pad(plaintext.Bytes(), aes.BlockSize)
		if err != nil {
			log.Panic(err)
		}

		//
		// Encrypt randomly using ecb or cbc
		//

		show := false

		if rand.Intn(2) == 0 {
			if show {
				log.Printf("ecb mode used")
			}

			key := randBytes(aes.BlockSize)
			ciphertext, err := aes.EcbEncrypt(padded, key)
			if err != nil {
				log.Panic(err)
			}
			return ciphertext

		} else {
			if show {
				log.Printf("cbc mode used")
			}

			key, iv := randBytes(aes.BlockSize), randBytes(aes.BlockSize)
			ciphertext, err := aes.CbcEncrypt(padded, key, iv)
			if err != nil {
				log.Panic(err)
			}
			return ciphertext
		}
	}

	//
	// Detect use of ecb vs cbc
	//

	for trial := 0; trial < 10; trial++ {
		// The input choice is arbitrary so long as it includes a number of repeated blocks
		input := make([]byte, aes.BlockSize * 10)
		output := oracle(input)

		split := func(src []byte) [][]byte {
			if len(src) % aes.BlockSize != 0 {
				log.Panic(errors.New("len(src) % blocksize != 0"))
			}

			chunks := make([][]byte, uint(len(src)) / aes.BlockSize)
			for i, j := 0, 0; i+aes.BlockSize <= len(src); i, j = i+aes.BlockSize, j+1 {
				chunks[j] = src[i:i+aes.BlockSize]
			}
			return chunks
		}

		allEqual := true
		chunks := split(output)
		for i := 2; i < len(chunks)-2; i++ {
			if !bytes.Equal(chunks[1], chunks[i]) {
				allEqual = false
				break
			}
		}

		if allEqual {
			log.Printf("trial %d: ecb mode detected", trial+1)
		} else {
			log.Printf("trial %d: cbc mode detected", trial+1)
		}
	}
}
