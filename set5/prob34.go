package main

import (
	"./dh"
	"../set2/aes"
	"../set2/pkcs7"
	"../set4/sha1"

	"bytes"
	"log"
	"math/big"
	"math/rand"
	"time"
)

func main() {
	//
	// Define the protocol functions
	//

	rand.Seed(time.Now().UnixNano())
	randBytes := func(n uint) []byte {
		b := make([]byte, n)
		rand.Read(b)
		return b
	}

	sendMsg := func(A, B *dh.Dh, plaintext string) []byte {
		s := A.Session(B)
		sum := sha1.Sum(s.Bytes())
		key := sum[:aes.BlockSize]

		iv := randBytes(aes.BlockSize)

		padded, err := pkcs7.Pad([]byte(plaintext), aes.BlockSize)
		if err != nil {
			log.Panic(err)
		}

		ciphertext, err := aes.CbcEncrypt(padded, key, iv)
		if err != nil {
			log.Panic(err)
		}

		ciphertext = append(ciphertext, iv...)
		return ciphertext
	}

	verifyMsg := func(A, B *dh.Dh, encryptedMsg []byte, plaintext string) bool {
		s := B.Session(A)
		sum := sha1.Sum(s.Bytes())
		key := sum[:aes.BlockSize]

		iv := encryptedMsg[len(encryptedMsg)-aes.BlockSize:len(encryptedMsg)]
		ciphertext := encryptedMsg[:len(encryptedMsg)-aes.BlockSize]

		padded, err := aes.CbcDecrypt(ciphertext, key, iv)
		if err != nil {
			log.Panic(err)
		}

		unpadded, err := pkcs7.Unpad(padded, aes.BlockSize)
		if err != nil {
			log.Panic(err)
		}

		return bytes.Equal(unpadded, []byte(plaintext))
	}

	A := dh.NewDhWithNist()
	B := dh.NewDhWithParams(A.P, A.G)

	plaintext := "test message"
	if !verifyMsg(A, B, sendMsg(A, B, plaintext), plaintext) {
		log.Panic("message unverified")
	}

	//
	// Implement the parameter-injection MITM attack
	//

	// s = (p ** x) % p => 0 for all values of x (except x=0)
	// x=0 should be sufficiently rare to not require accommodating it

	decryptMsg := func(encryptedMsg []byte) string {
		s := big.NewInt(0)
		sum := sha1.Sum(s.Bytes())
		key := sum[:aes.BlockSize]

		iv := encryptedMsg[len(encryptedMsg)-aes.BlockSize:len(encryptedMsg)]
		ciphertext := encryptedMsg[:len(encryptedMsg)-aes.BlockSize]

		padded, err := aes.CbcDecrypt(ciphertext, key, iv)
		if err != nil {
			log.Panic(err)
		}

		unpadded, err := pkcs7.Unpad(padded, aes.BlockSize)
		if err != nil {
			log.Panic(err)
		}

		return string(unpadded)
	}

	A = dh.NewDhWithNist()
	B = dh.NewDhWithParams(A.P, A.G)

	fakeA := dh.NewDhWithNist(); fakeA.A = A.P
	fakeB := dh.NewDhWithParams(A.P, A.G); fakeB.A = A.P

	plaintext1 := "proceed to rally point"
	if !verifyMsg(fakeA, fakeB, sendMsg(fakeA, fakeB, plaintext1), plaintext1) {
		log.Panic("message unverified")
	}

	intercepted1 := sendMsg(fakeA, fakeB, plaintext1)
	log.Printf("decrypted A->B intercepted message: %q", decryptMsg(intercepted1))

	plaintext2 := "affirmative, eta 1h"
	if !verifyMsg(fakeB, fakeA, sendMsg(fakeB, fakeA, plaintext2), plaintext2) {
		log.Panic("message unverified")
	}

	intercepted2 := sendMsg(fakeB, fakeA, plaintext2)
	log.Printf("decrypted B->A intercepted message: %q", decryptMsg(intercepted2))
}
