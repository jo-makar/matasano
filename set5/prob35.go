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
	// Implement the parameter-injection MITM attacks
	//

	decryptMsgError := func(encryptedMsg []byte, sessionKey *big.Int) (string, error) {
		sum := sha1.Sum(sessionKey.Bytes())
		key := sum[:aes.BlockSize]

		iv := encryptedMsg[len(encryptedMsg)-aes.BlockSize:len(encryptedMsg)]
		ciphertext := encryptedMsg[:len(encryptedMsg)-aes.BlockSize]

		padded, err := aes.CbcDecrypt(ciphertext, key, iv)
		if err != nil {
			return "", err
		}

		unpadded, err := pkcs7.Unpad(padded, aes.BlockSize)
		if err != nil {
			return "", err
		}

		return string(unpadded), nil
	}

	decryptMsg := func(encryptedMsg []byte, sessionKey *big.Int) string {
		decryptedMsg, err := decryptMsgError(encryptedMsg, sessionKey)
		if err != nil {
			log.Panic(err)
		}
		return decryptedMsg
	}

	// Case 1, set g = 1 for B:
	//     B = (g ** b) % p = (1 ** b) % p => 1 for all values of b (except b=0)
	//     treat b=0 as sufficiently rare as to not accommodate it
	//
	// Then A's session key becomes:
	//     s = (B ** a) % p = (1 ** a) % p => 1 for all values of a (except a=0)
	//     treat a=0 as sufficiently rare as to not accommodate it

	A = dh.NewDhWithNist()
	B = dh.NewDhWithParams(A.P, big.NewInt(1))

	plaintext1 := "proceed to rally point"
	intercepted1 := decryptMsg(sendMsg(A, B, plaintext1), big.NewInt(1))
	log.Printf("decrypted A->B intercepted message 1: %q", intercepted1)
	if intercepted1 != plaintext1 {
		log.Panic("intercepted message incorrectly decrypted")
	}

	// Case 2, set g = p for B:
	//     B = (g ** b) % p = (p ** b) % p => 0 for all values of b (except b=0)
	//     treat b=0 as sufficiently rare as to not accommodate it
	//
	// Then A's session key becomes:
	//     s = (B ** a) % p = (0 ** a) % p => 0 for all values of a (except a=0)
	//     treat a=0 as sufficiently rare as to not accommodate it

	A = dh.NewDhWithNist()
	B = dh.NewDhWithParams(A.P, A.P)

	plaintext2 := "what is your eta?"
	intercepted2 := decryptMsg(sendMsg(A, B, plaintext2), big.NewInt(0))
	log.Printf("decrypted A->B intercepted message 2: %q", intercepted2)
	if intercepted2 != plaintext2 {
		log.Panic("intercepted message incorrectly decrypted")
	}

	// Case 3, set g = p-1 for B:
	//     B = (g ** b) % p = ((p-1) ** b) % p => ... => 1   if b is even including zero
	//                                                   p-1 if b is odd
	//     Determined using properties of modular arithmetic
	//     Ref: https://www.khanacademy.org/computing/computer-science/cryptography/modarithmetic/a/what-is-modular-arithmetic
	//
	// Then A's session key becomes:
	//     if b is even:
	//         s = (B ** a) % p = (1 ** a) % p => 1 for all values of a (except a=0)
	//         treat a=0 as sufficiently rare as to not accommodate it
	//     if b is odd:
	//         s = (B ** a) % p = ((p-1) ** a) % p => ... => 1   if a is even including zero
	//                                                       p-1 if a is odd

	A = dh.NewDhWithNist()
	B = dh.NewDhWithParams(A.P, new(big.Int).Sub(A.P, big.NewInt(1)))

	plaintext3 := "consider charlie suspect"
	encryptedMsg := sendMsg(A, B, plaintext3)

	var intercepted3 string
	for _, sessionKey := range []*big.Int{ big.NewInt(1), new(big.Int).Sub(A.P, big.NewInt(1)) } {
		intercepted, err := decryptMsgError(encryptedMsg, sessionKey)
		if err == nil {
			intercepted3 = intercepted

			var sessionKeyName string
			if sessionKey.Cmp(big.NewInt(1)) == 0 {
				sessionKeyName = "1"
			} else {
				sessionKeyName = "p-1"
			}

			log.Printf("decrypted A->B intercepted message 3: %q using session key %s",
			           intercepted, sessionKeyName)

			break
		}
	}
	if intercepted3 != plaintext3 {
		log.Panic("intercepted message incorrectly decrypted")
	}
}
