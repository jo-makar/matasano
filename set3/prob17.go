package main

import (
	"../set1/base64"
	"../set2/aes"
	"../set2/pkcs7"

	"bytes"
	"log"
	"math/rand"
	"time"
)

func main() {
	//
	// Define the oracle
	//

	rand.Seed(time.Now().UnixNano())
	randBytes := func(n uint) []byte {
		b := make([]byte, n)
		rand.Read(b)
		return b
	}

	type Oracle struct {
		Call     func() ([]byte, []byte)
		Validate func([]byte, []byte) bool

		key []byte
	}

	oracle := func() *Oracle {
		oracle := Oracle{ key: randBytes(aes.BlockSize) }

		oracle.Call = func() ([]byte, []byte) {
			plaintexts := []string{
				"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
				"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
				"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
				"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
				"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
				"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
				"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
				"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
				"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
				"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
			}

			plaintext := plaintexts[rand.Intn(len(plaintexts))]
			decoded, err := base64.Decode(plaintext)
			if err != nil {
				log.Panic(err)
			}

			padded, err := pkcs7.Pad(decoded, aes.BlockSize)
			if err != nil {
				log.Panic(err)
			}

			iv := randBytes(aes.BlockSize)
			ciphertext, err := aes.CbcEncrypt(padded, oracle.key, iv)
			if err != nil {
				log.Panic(err)
			}
			return ciphertext, iv
		}

		oracle.Validate = func(ciphertext, iv []byte) bool {
			padded, err := aes.CbcDecrypt(ciphertext, oracle.key, iv)
			if err != nil {
				log.Panic(err)
			}

			_, err = pkcs7.Unpad(padded, aes.BlockSize)
			return err == nil
		}

		return &oracle
	}()

	for trial := 0; trial < 10; trial++ {
		ciphertext, iv := oracle.Call()
		plaintext := make([]byte, len(ciphertext))

		for block := 0; block < len(ciphertext)/aes.BlockSize; block++ {

			//
			// Determine the last byte (potentially bytes) of a ciphertext block
			//

			// In CBC decryption, the ciphertext block is decrypted then xor'ed with the preceding
			// ciphertext block to produce the plaintext block, or in symbolic terms:
			//
			//     Pn = D(Cn) xor Cn-1      where Pn is the nth plaintext block
			//                                    Cn is the nth ciphertext block
			//                              and   D() is the decryption process
			//
			// Create a fake (random) ciphertext block, call it Fn, followed by the target block.
			// If this fake block has valid padding then there are 16 (block length) possibilities:
			//
			//     1st: D(Cn)[15]    xor Fn[15]    == {1}
			//     2nd: D(Cn)[14,15] xor Fn[14,15] == {2,2}
			//     3rd: D(Cn)[13-15] xor Fn[13-15] == {3,3,3}
			//     ...
			//
			// Rearranging terms and using the first formula, the last bytes can now be determined:
			//
			//     1st: Pn[15]    == (Fn[15     xor {1})     xor Cn-1[15]
			//     2nd: Pn[14,15] == (Fn[14,15] xor {2,2})   xor Cn-1[14,15]
			//     3rd: Pn[13-15] == (Fn[13-15] xor {3,3,3}) xor Cn-1[13-15]
			//     ...

			var decryptedBlock []byte

			targetBlock := ciphertext[block*aes.BlockSize : (block+1)*aes.BlockSize]
			fakeBlock := randBytes(aes.BlockSize)

			for i := 0; i < 256; i++ {
				fakeBlock[aes.BlockSize-1] = byte(i)

				testBlocks := make([]byte, 2*aes.BlockSize)
				copy(testBlocks[0*aes.BlockSize:1*aes.BlockSize], fakeBlock)
				copy(testBlocks[1*aes.BlockSize:2*aes.BlockSize], targetBlock)

				if oracle.Validate(testBlocks, make([]byte, aes.BlockSize)) {

					// Determine the padding by changing one bit from the left side of the block.
					// The index at which the padding is no longer valid indicate the padding byte.

					found := false
					for j := 0; j < aes.BlockSize; j++ {
						testBlocks := make([]byte, 2*aes.BlockSize)
						copy(testBlocks[0*aes.BlockSize:1*aes.BlockSize], fakeBlock)
						copy(testBlocks[1*aes.BlockSize:2*aes.BlockSize], targetBlock)
						testBlocks[j] ^= 1

						if !oracle.Validate(testBlocks, make([]byte, aes.BlockSize)) {
							padding := byte(aes.BlockSize - j)
							for k := j; k < aes.BlockSize; k++ {
								decryptedBlock = append(decryptedBlock, padding ^ fakeBlock[k])
							}

							found = true
							break
						}
					}

					if !found {
						log.Panic("padding undetermined")
					}

					break
				}
			}

			if len(decryptedBlock) == 0 {
				log.Panic("last bytes undetermined")
			}

			//
			// Decrypt the remaining bytes of the ciphertext block.
			// Essentially an extension of the preceding process.
			//

			for len(decryptedBlock) < aes.BlockSize {
				padding := byte(len(decryptedBlock) + 1)
				found := false

				for i := 0; i < 256; i++ {
					var fakeBlock bytes.Buffer
					fakeBlock.Write(randBytes(uint(aes.BlockSize-1 - len(decryptedBlock))))
					fakeBlock.WriteByte(byte(i))
					for _, b := range decryptedBlock { fakeBlock.WriteByte(b ^ padding) }

					testBlocks := make([]byte, 2*aes.BlockSize)
					copy(testBlocks[0*aes.BlockSize:1*aes.BlockSize], fakeBlock.Bytes())
					copy(testBlocks[1*aes.BlockSize:2*aes.BlockSize], targetBlock)

					if oracle.Validate(testBlocks, make([]byte, aes.BlockSize)) {
						decryptedBlock = append([]byte{byte(i) ^ padding}, decryptedBlock...)
						found = true
						break
					}
				}

				if !found {
					log.Panic("padding undetermined")
				}
			}

			//
			// Convert the decrypted block to (padded) plaintext
			//

			var prevBlock []byte
			if block == 0 {
				prevBlock = iv
			} else {
				prevBlock = ciphertext[(block-1)*aes.BlockSize : block*aes.BlockSize]
			}

			for i := 0; i < aes.BlockSize; i++ {
				plaintext[block*aes.BlockSize + i] = decryptedBlock[i] ^ prevBlock[i]
			}
		}

		unpadded, err := pkcs7.Unpad(plaintext, aes.BlockSize)
		if err != nil {
			log.Panic(err)
		}

		log.Printf("trial %2d: %q", trial+1, unpadded)
	}
}
