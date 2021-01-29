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

	type Oracle struct {
		Call func([]byte) []byte

		key     []byte
		postfix []byte
	}

	oracle := func() *Oracle {
		oracle := Oracle{ key: randBytes(aes.BlockSize) }

		encodedPostfix := `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
`

		postfix, err := base64.Decode(strings.ReplaceAll(encodedPostfix, "\n", ""))
		if err != nil {
			log.Panic(err)
		}
		oracle.postfix = postfix

		oracle.Call = func(input []byte) []byte {
			var plaintext bytes.Buffer
			plaintext.Write(randBytes(uint(rand.Intn(100))))
			plaintext.Write(input)
			plaintext.Write(oracle.postfix)

			padded, err := pkcs7.Pad(plaintext.Bytes(), aes.BlockSize)
			if err != nil {
				log.Panic(err)
			}

			ciphertext, err := aes.EcbEncrypt(padded, oracle.key)
			if err != nil {
				log.Panic(err)
			}
			return ciphertext
		}

		return &oracle
	}()

	// Not bothering to determining the cipher block size nor verifying ECB mode.
	// Those procedures would be nearly identical to those from problem 12.

	//
	// Define a higher-level oracle:
	//
	// Prefix the input with a series of blocks that will be detectable in the output
	// when the random prefix happens to end on a block boundary.
	// This implies that one execution of the higher oracle involves many oracle executions.
	//

	inputPrefix := make([]byte, 5 * aes.BlockSize)
	for i := 0 * aes.BlockSize; i < 1 * aes.BlockSize; i++ { inputPrefix[i] = byte(i) }
	for i := 1 * aes.BlockSize; i < 2 * aes.BlockSize; i++ { inputPrefix[i] = 'A' }
	for i := 2 * aes.BlockSize; i < 3 * aes.BlockSize; i++ { inputPrefix[i] = byte(i % aes.BlockSize) }
	for i := 3 * aes.BlockSize; i < 4 * aes.BlockSize; i++ { inputPrefix[i] = 'B' }
	for i := 4 * aes.BlockSize; i < 5 * aes.BlockSize; i++ { inputPrefix[i] = byte(i % aes.BlockSize) }

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

	suffix := func(n uint) string {
		table := []string{"th", "st", "nd", "rd"}
		if n < uint(len(table)) {
			return table[n]
		} else {
			return "th"
		}
	}

	found := false
	outputPrefix := make([]byte, len(inputPrefix))

  	for i := 0; !found && i < 1000; i++ {
		output := oracle.Call(inputPrefix)
		outputBlocks := split(output)

		for j := 0; j < len(outputBlocks) - 5; j++ {
			if  bytes.Equal(outputBlocks[j],   outputBlocks[j+2]) &&
			    bytes.Equal(outputBlocks[j],   outputBlocks[j+4]) &&
			   !bytes.Equal(outputBlocks[j],   outputBlocks[j+1]) &&
			   !bytes.Equal(outputBlocks[j],   outputBlocks[j+3]) &&
			   !bytes.Equal(outputBlocks[j+1], outputBlocks[j+3]) {

				log.Printf("match found on %d%s iteration", i, suffix(uint(i)))
				copy(outputPrefix, output[j*aes.BlockSize:(j+5)*aes.BlockSize])
				found = true
				break
			}
 		}
	}

	if !found {
		log.Panic(errors.New("match not found"))
	}

	// Verify the found output by searching for it repeatedly

	count := 0
	for i := 0; i < 1000; i++ {
		if bytes.Contains(oracle.Call(inputPrefix), outputPrefix) {
			count++
		}
	}

	if count == 0 {
		log.Panic(errors.New("match not verified"))
	}
	log.Printf("match verified, found %d times in 1000 tests", count)

	type HigherOracle struct {
		Call func([]byte) []byte

		Stats      map[string]int
		ResetStats func()

		oracle       *Oracle
		inputPrefix  []byte
		outputPrefix []byte
	}

	higherOracle := func(oracle *Oracle, inputPrefix, outputPrefix []byte) *HigherOracle {
		higherOracle := HigherOracle{
			      oracle: oracle,
			 inputPrefix: inputPrefix,
 			outputPrefix: outputPrefix,

			Stats: make(map[string]int),
		}

		higherOracle.ResetStats = func() {
			higherOracle.Stats = make(map[string]int)
		}

		higherOracle.Call = func(input []byte) []byte {
			for {
				higherOracle.Stats["execs"]++

				higherInput := make([]byte, len(higherOracle.inputPrefix) + len(input))
				copy(higherInput, higherOracle.inputPrefix)
				copy(higherInput[len(higherOracle.inputPrefix):len(higherInput)], input)

				ciphertext := higherOracle.oracle.Call(higherInput)
				if idx := bytes.Index(ciphertext, higherOracle.outputPrefix); idx == -1 {
					higherOracle.Stats["skips"]++
				} else {
					return ciphertext[idx+len(higherOracle.outputPrefix):]
				}
			}
		}

		return &higherOracle
	}(oracle, inputPrefix, outputPrefix)

	//
	// Follow the same process as used for problem 12 with the higher-level oracle
  	//

  	// Determine the length of the postfixed string.
  	// Look for the first change in ciphertext length as the plaintext length increases,
  	// then the postfixed string length is the (prev ciphertext length - 1) - prev input string length.

  	postfixLen := 0

  	for i := 1; i < 100; i++ {
	  	output1 := higherOracle.Call(make([]byte, i-1))
	  	output2 := higherOracle.Call(make([]byte, i))

	  	if len(output2) > len(output1) {
		  	postfixLen = (len(output1)-1) - (i-1)
		  	log.Printf("postfix length determined to be %d", postfixLen)
		  	log.Printf("which took %d executions with %d skips", higherOracle.Stats["execs"], higherOracle.Stats["skips"])
		  	higherOracle.ResetStats()
		  	break
	  	}
  	}

  	if postfixLen == 0 {
	  	log.Panic(errors.New("postfix length undetermined"))
  	} else if postfixLen != len(oracle.postfix) {
	  	log.Panic(errors.New("postfix length incorrect"))
  	}

	// Determine each byte of the postfixed string.
	// Use input to shift first byte of postfixed string as the last byte of the block,
	// Then iterate through the possiblities until a match is found.
	// Repeat for the remaining bytes of the postfixed string.

	zeroBytes := func(n uint) []byte {
		return make([]byte, n)
	}

	postfix := make([]byte, postfixLen)

	for i := 0; i < postfixLen; i++ {
		targetInput := make([]byte, (aes.BlockSize - 1) - (i % aes.BlockSize))
		targetOutput := higherOracle.Call(targetInput)

		k := i / aes.BlockSize // Integer division
		found := false
		for j := 0; j < 256; j++ {

			var testInput bytes.Buffer
			testInput.Write(zeroBytes(uint(aes.BlockSize-1 - (i%aes.BlockSize))))
			testInput.Write(postfix[0:i])
			testInput.WriteByte(byte(j))

			testOutput := higherOracle.Call(testInput.Bytes())
			s, e := k * aes.BlockSize, (k+1) * aes.BlockSize
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
	if !bytes.Equal(postfix, oracle.postfix) {
		log.Panic(errors.New("postfix != oracle.postfix"))
	}
	log.Printf("which took %d executions with %d skips", higherOracle.Stats["execs"], higherOracle.Stats["skips"])
}
