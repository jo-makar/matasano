package main

import (
	"./mt19937"
	"../set1/hex"

	"bytes"
	"errors"
	"log"
	"math/rand"
	"time"
)

func main() {
	//
	// MT19937 stream cipher
	//

	rand.Seed(time.Now().UnixNano())

	encrypt := func(plaintext []byte, key uint32) []byte {
		rng := mt19937.NewMt19937Seed(uint32(key))

		w := rng.Uint32() // Current random number/word
		b := 0            // Byte index into word: 0-3

		ciphertext := make([]byte, len(plaintext))
		for i := 0; i <len(plaintext); i++ {
			ciphertext[i] = plaintext[i] ^ uint8(w >> (8*b))

			b = (b + 1) % 4
			if b == 0 {
				w = rng.Uint32()
			}
		}
		return ciphertext
	}

	decrypt := func(ciphertext []byte, key uint32) []byte {
		return encrypt(ciphertext, key)
	}

	//
	// Recover a key given knowledge of the plaintext
	//

	randBytes := func(n uint) []byte {
		b := make([]byte, n)
		rand.Read(b)
		return b
	}

	key := rand.Uint32() & 0x0000ffff
	plaintext := append(randBytes(uint(5 + rand.Intn(11))), []byte("AAAAAAAAAAAAAA")...)
	ciphertext := encrypt(plaintext, key)

	found := false
	for testKey := 0; testKey < 0x10000; testKey++ {
		testPlaintext := decrypt(ciphertext, uint32(testKey))
		if bytes.Equal(testPlaintext[len(testPlaintext)-14:], []byte("AAAAAAAAAAAAAA")) {
			log.Printf("seed = %#04x", testKey)
			found = true
			break
		}
	}

	if !found {
		log.Panic("key not found")
	}

	//
	// Recover a password reset token key based on current time
	//

	resetToken := func() string {
		rng := mt19937.NewMt19937Seed(uint32(time.Now().Unix()))

		w := rng.Uint32()
		b := 0

		token := make([]byte, 10)
		for i := 0; i < len(token); i++ {
			token[i] = uint8(w >> (8*b))

			b = (b + 1) % 4
			if b == 0 {
				w = rng.Uint32()
			}
		}

		encoded, _ := hex.Encode(token)
		return encoded
	}

	token := resetToken()

	testSeed := uint32(time.Now().Unix())

	found = false
	for i := 0; i < 300; i++ {
		testToken, _ := hex.Encode(encrypt(make([]byte, 10), testSeed))
		if testToken == token {
			log.Printf("seed = %#04x (%d iterations)", testSeed, i)
			found = true
			break
		}

		testSeed--
	}

	if !found {
		log.Panic(errors.New("seed not found"))
	}
}
