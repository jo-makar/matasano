package main

import (
	"./aes"
	"./pkcs7"
	"../set1/base64"

	"bytes"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"
)

func main() {
	//
	// Define the oracle function
	//

	rand.Seed(time.Now().UnixNano())

	randBytes := func(n uint) []byte {
		b := make([]byte, n)
		rand.Read(b)
		return b
	}

	oracleKey := randBytes(aes.BlockSize)

	encodedOraclePostfix := `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
`
	oraclePostfix, err := base64.Decode(strings.ReplaceAll(encodedOraclePostfix, "\n", ""))
	if err != nil {
		log.Panic(err)
	}

	oracle := func(input []byte) []byte {
		var plaintext bytes.Buffer
		plaintext.Write(input)
		plaintext.Write(oraclePostfix)

		padded, err := pkcs7.Pad(plaintext.Bytes(), aes.BlockSize)
		if err != nil {
			log.Panic(err)
		}

		ciphertext, err := aes.EcbEncrypt(padded, oracleKey)
		if err != nil {
			log.Panic(err)
		}
		return ciphertext
	}

	//
	// Determine the block size of the cipher
	//

	// Look for the first change in ciphertext length as the plaintext length increases.
	// The change in the ciphertext length is the cipher block size.

	blockSize := 0

	for i := 1; i < 100; i++ {
		output1 := oracle(make([]byte, i-1))
		output2 := oracle(make([]byte, i))

		if len(output2) > len(output1) {
			blockSize = len(output2) - len(output1)
			log.Printf("blocksize determined to be %d", blockSize)
			break
		}
	}

	if blockSize == 0 {
		log.Panic(errors.New("blocksize undetermined"))
	}

	//
	// Verify ECB mode is being used
	//

	output := oracle(make([]byte, 2 * blockSize))
	if bytes.Equal(output[0:blockSize], output[blockSize:blockSize*2]) {
		log.Printf("ecb mode verified")
	} else {
		log.Panic(errors.New("ecb mode unverified"))
	}

	//
	// Determine the length of the postfixed string.
	//

	// Look for the first change in ciphertext length as the plaintext length increases,
	// then the postfixed string length is the (prev ciphertext length - 1) - prev input string length.

	postfixLen := 0

	for i := 1; i < 100; i++ {
		output1 := oracle(make([]byte, i-1))
		output2 := oracle(make([]byte, i))

		if len(output2) > len(output1) {
			postfixLen = (len(output1)-1) - (i-1)
			log.Printf("postfix length determined to be %d", postfixLen)
			break
		}
	}

	if postfixLen == 0 {
		log.Panic(errors.New("postfix length undetermined"))
	} else if postfixLen != len(oraclePostfix) {
		log.Panic(errors.New("postfix length incorrect"))
	}

	//
	// Determine each byte of the postfixed string
	//

	// Use input to shift first byte of postfixed string as the last byte of the block,
	// Then iterate through the possiblities until a match is found.
	// Repeat for the remaining bytes of the postfixed string.

	zeroBytes := func(n uint) []byte {
		return make([]byte, n)
	}

	postfix := make([]byte, postfixLen)

	for i := 0; i < postfixLen; i++ {
		targetInput := make([]byte, (blockSize - 1) - (i % blockSize))
		targetOutput := oracle(targetInput)

		k := i / blockSize // Integer division
		found := false
		for j := 0; j < 256; j++ {

			var testInput bytes.Buffer
			testInput.Write(zeroBytes(uint(blockSize-1 - (i%blockSize))))
			testInput.Write(postfix[0:i])
			testInput.WriteByte(byte(j))

			testOutput := oracle(testInput.Bytes())
			s, e := k * blockSize, (k+1) * blockSize
			if bytes.Equal(testOutput[s:e], targetOutput[s:e]) {
				postfix[i] = byte(j)
				found = true
				break
			}
		}

		if !found {
			log.Panic(fmt.Errorf("byte %d not found", i))
		}
	}

	log.Printf("postfix = %v (%q)", postfix, postfix)
	if !bytes.Equal(postfix, oraclePostfix) {
		log.Panic(errors.New("postfix != oraclePostfix"))
	}
}
