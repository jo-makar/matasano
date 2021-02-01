package main

import (
	"./aes"
	"../set1/base64"
	"../set1/score"

	"bufio"
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

	var basePath string 
	if _, p, _, ok := runtime.Caller(0); !ok {
		log.Panic(errors.New("runtime.Caller() failed"))
	} else {
		basePath = filepath.Dir(p)
	}

	inputFile, err := os.Open(filepath.Join(basePath, "prob20.txt"))
	if err != nil {
		log.Panic(err)
	}
	defer inputFile.Close()

	var plaintexts [][]byte
	scanner := bufio.NewScanner(inputFile)
	for scanner.Scan() {
		plaintext, err := base64.Decode(scanner.Text())
		if err != nil {
			log.Panic(err)
		}
		plaintexts = append(plaintexts, plaintext)
	}
	if err := scanner.Err(); err != nil {
		log.Panic(err)
	}

	key := randBytes(aes.BlockSize)
	nonce := uint64(0)

	ciphertexts := make([][]byte, len(plaintexts))
	for i := 0; i < len(plaintexts); i++ {
		ciphertexts[i], err = aes.CtrEncrypt(plaintexts[i], key, nonce)
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

		log.Printf("%d: %q %q", i, derivedPlaintext, plaintexts[i])
	}

	// The corpus used (The Brothers Karamazov) to generate the scoring table is long;
	// making lowercase letter far more common than uppercase letters.
	// This skews the probabilities making the first column (technically) incorrect.
	// This can be dealt with by using an alternate corpus.
	//
	// Also note the last few bytes of the longer ciphertexts are incorrect due to lack of data,
	// this is a more difficult problem to solve algorithmically but can dealt with using context.
}
