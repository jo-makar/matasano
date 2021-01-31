package main

import (
	"./aes"
	"../set1/base64"
	"../set1/score"

	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

func main() {
	//
	// Encrypt the plaintexts
 	//

	rand.Seed(time.Now().UnixNano())
	randBytes := func(n uint) []byte {
		b := make([]byte, n)
		rand.Read(b)
		return b
	}

	plaintexts := []string{
		"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
		"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
		"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
		"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
		"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
		"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
		"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
		"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
		"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
		"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
		"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
		"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
		"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
		"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
		"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
		"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
		"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
		"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
		"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
		"U2hlIHJvZGUgdG8gaGFycmllcnM/",
		"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
		"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
		"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
		"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
		"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
		"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
		"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
		"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
		"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
		"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
		"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
		"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
		"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
		"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
		"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
		"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
	}

	key := randBytes(aes.BlockSize)
	nonce := uint64(0)

	ciphertexts := make([][]byte, len(plaintexts))
	for i := 0; i < len(plaintexts); i++ {
		decoded, err := base64.Decode(plaintexts[i])
		if err != nil {
			log.Panic(err)
		}

		ciphertexts[i], err = aes.CtrEncrypt(decoded, key, nonce)
		if err != nil {
			log.Panic(err)
		}
	}

	//
	// Statistically determine each byte of the keystream
	//

	// Because the keystream is used repeatedly can gather all of the ciphertext bytes by index,
	// and determine the most-likely keystream byte based on the most-likey resulting plaintext bytes.

	var corpusTable1, corpusTable2 *score.Table

	makeTable := func(reader io.Reader, n uint) *score.Table {
		table, err := score.NewTable(reader, n)
		if err != nil {
			log.Panic(err)
		}
		return table
	}

	if _, p, _, ok := runtime.Caller(0); !ok {
		log.Panic(errors.New("runtime.Caller() failed"))
	} else {
		path := filepath.Join(filepath.Dir(p), "../set1/The Brothers Karamazov.txt")
		file, err := os.Open(path)
		if err != nil {
			log.Panic(err)
		}
		defer file.Close()

		corpusTable1 = makeTable(file, 1)
		if _, err = file.Seek(0, 0); err != nil {
			log.Panic(err)
		}
		corpusTable2 = makeTable(file, 2)
	}

	maxLen := 0
	for _, ciphertext := range ciphertexts {
		if len(ciphertext) > maxLen {
			maxLen = len(ciphertext)
		}
	}
	keystream := make([]byte, maxLen)

	for i := 0; i < len(keystream); i++ {
		var buf bytes.Buffer
		for _, ciphertext := range ciphertexts {
			if len(ciphertext) > i {
				buf.WriteByte(ciphertext[i])
			}
		}
		ciphertextStream := buf.Bytes()

		var bestScore float32 = math.MaxFloat32
		var bestByte byte

		for b := 0; b < 256; b++ {
			plaintextStream := make([]byte, len(ciphertextStream))
			for j := 0; j < len(plaintextStream); j++ {
				plaintextStream[j] = ciphertextStream[j] ^ byte(b)
			}

			table1 := makeTable(bytes.NewReader(plaintextStream), 1)
			table2 := makeTable(bytes.NewReader(plaintextStream), 2)
			if score := corpusTable1.Compare(table1) + corpusTable2.Compare(table2); score < bestScore {
				bestScore, bestByte = score, byte(b)
			}
		}

		keystream[i] = bestByte

		fmt.Printf(".")
	}
	fmt.Printf("\n")

	for i := 0; i < len(ciphertexts); i++ {
		derivedPlaintext := make([]byte, len(ciphertexts[i]))
		for j := 0; j < len(derivedPlaintext); j++ {
			derivedPlaintext[j] = ciphertexts[i][j] ^ keystream[j]
		}

		actualPlaintext, err := base64.Decode(plaintexts[i])
		if err != nil {
			log.Panic(err)
		}

		log.Printf("%d: %q %q", i, derivedPlaintext, actualPlaintext)
	}

	// The corpus used (The Brothers Karamazov) to generate the scoring table is long;
	// making lowercase letter far more common than uppercase letters.
	// This skews the probabilities making the first column (technically) incorrect.
	// This can be dealt with by using an alternate corpus.
	//
	// Also note the last few bytes of the longer ciphertexts are incorrect due to lack of data,
	// this is a more difficult problem to solve algorithmically but can dealt with using context.
}
