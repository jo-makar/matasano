package main

import (
	"../set1/base64"
	aesEcb "../set2/aes"
	aesCtr "../set3/aes"

	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

func main() {
	//
	// Retrieve and encrypt the plaintext
	//

	// The problem didn't explicitly mention the file contents are ecb-encrypted with the key "YELLOW SUBMARINE"

	var origCiphertext []byte

	if _, p, _, ok := runtime.Caller(0); !ok {
		log.Panic(errors.New("runtime.Caller() failed"))
	} else {
		path := filepath.Join(filepath.Dir(p), "prob25.txt")
		file, err := os.Open(path)
		if err != nil {
			log.Panic(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			decoded, err := base64.Decode(scanner.Text())
			if err != nil {
				log.Panic(err)
			}
			origCiphertext = append(origCiphertext, decoded...)
		}
		if err := scanner.Err(); err != nil {
			log.Panic(err)
		}
	}

	plaintext, err := aesEcb.EcbDecrypt(origCiphertext, []byte("YELLOW SUBMARINE"))
	if err != nil {
		log.Panic(err)
	}

	rand.Seed(time.Now().UnixNano())

	randBytes := func(n uint) []byte {
		b := make([]byte, n)
		rand.Read(b)
		return b
	}

	key := randBytes(aesCtr.BlockSize)
	nonce := rand.Uint64()

	ciphertext, err := aesCtr.CtrEncrypt(plaintext, key, nonce)
	if err != nil {
		log.Panic(err)
	}

	//
	// Define the edit function
	//

	edit := func(ciphertext, key []byte, nonce uint64, offset uint, newPlaintext []byte) []byte {
		plaintext, err := aesCtr.CtrDecrypt(ciphertext, key, nonce)
		if err != nil {
			log.Panic(err)
		}

		editedPlaintext := make([]byte, len(plaintext))
		copy(editedPlaintext, plaintext)

		for i, j := offset, 0; j < len(newPlaintext); i, j = i+1, j+1 {
			if i < uint(len(editedPlaintext)) {
				editedPlaintext[i] = newPlaintext[j]
			} else {
				editedPlaintext = append(editedPlaintext, newPlaintext[j])
			}
		}

		editedCiphertext, err := aesCtr.CtrEncrypt(editedPlaintext, key, nonce)
		if err != nil {
			log.Panic(err)
		}
		return editedCiphertext
	}

	//
	// Recover the original plaintext
	//
	// Change all the plaintext to be zeros, then the ciphertext will be the encrypted keystream.
	// The encrypted keystream can be used to directly decrypt the original ciphertext.
	//

	keystream := edit(ciphertext, key, nonce, 0, make([]byte, len(ciphertext)))

	recoveredPlaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		recoveredPlaintext[i] = ciphertext[i] ^ keystream[i]
	}

	if !bytes.Equal(recoveredPlaintext, plaintext) {
		log.Panic("recovered plaintext does not match")
	}
	fmt.Print(string(recoveredPlaintext))
}
