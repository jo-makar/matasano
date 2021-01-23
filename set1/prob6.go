package main

import (
	"./base64"
	"./hamming"
	"./score"
	"./xor"

	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"runtime"
)

func main() {
	//
	// Build n-length string occurrence tables
	//

	var basePath string
	if _, p, _, ok := runtime.Caller(0); !ok {
		log.Panic(errors.New("runtime.Caller() failed"))
	} else {
		basePath = filepath.Dir(p)
	}

	corpusFile, err := os.Open(filepath.Join(basePath, "The Brothers Karamazov.txt"))
	if err != nil {
		log.Panic(err)
	}
	defer corpusFile.Close()

	makeTable := func(reader io.Reader, n uint) *score.Table {
		table, err := score.NewTable(reader, n)
		if err != nil {
			log.Panic(err)
		}
		return table
	}

	corpusTable1 := makeTable(corpusFile, 1)
	if _, err := corpusFile.Seek(0, 0); err != nil {
		log.Panic(err)
	}
	corpusTable2 := makeTable(corpusFile, 2)
	if _, err := corpusFile.Seek(0, 0); err != nil {
		log.Panic(err)
	}

	//
	// Retrieve and decode the ciphertext
	//

	inputFile, err := os.Open(filepath.Join(basePath, "prob6.txt"))
	if err != nil {
		log.Panic(err)
	}
	defer inputFile.Close()

	var ciphertext []byte

	scanner := bufio.NewScanner(inputFile)
	for scanner.Scan() {
		line, err := base64.Decode(scanner.Text())
		if err != nil {
			log.Panic(err)
		}

		ciphertext = append(ciphertext, line...)
	}
	if err := scanner.Err(); err != nil {
		log.Panic(err)
	}


	//
	// Guess the keysize as n where:
	// The ciphertext chunks of length n have the lowest normalized Hamming distance
	//

	// Split a byte array/slice into n-length chunks
	split := func(src []byte, n uint) [][]byte {
		// Allow last chunk to be shorter than n?
		shortOk := false

		if n == 0 {
			log.Panic("split: n == 0")
		}

		chunks := make([][]byte, uint(len(src)) / n)

		for i, j := uint(0), 0; i+n <= uint(len(src)); i, j = i+n, j+1 {
			chunks[j] = src[i:i+n]
		}

		if shortOk && uint(len(src)) % n > 0 {
			chunks = append(chunks, src[uint(len(src))/n * n:])
		}

		return chunks
	}

	average := func(d []float32) float32 {
		var t float32
		for _, v := range d {
			t += v
		}
		return t / float32(len(d))
	}

	var bestAvgDist float32 = math.MaxFloat32
	var bestKeysize uint

	for keysize := uint(2); keysize <= 40; keysize++ {
		chunks := split(ciphertext, keysize)

		var dists []float32
		for i := 0; i < len(chunks)-1; i++ {
			for j := i+1; j < len(chunks); j++ {
				normDist := float32(hamming.Dist(chunks[i], chunks[j])) / float32(keysize)
				dists = append(dists, normDist)
			}
		}

		if avgDist := average(dists); avgDist < bestAvgDist {
			bestAvgDist, bestKeysize = avgDist, keysize
		}

		fmt.Print(".")
	}
	fmt.Print("\n")

	log.Printf("best keysize is %d with avg. norm. hamming dist. of %.2f", bestKeysize, bestAvgDist)

	//
	// Transpose the ciphertext into blocks and identify the most-likely (single-byte) key for each block
	//

	keysize := bestKeysize
	blocks := make([][]byte, keysize)

	for i := uint(0); i < keysize; i++ {
		for j := i; j < uint(len(ciphertext)); j += keysize {
			blocks[i] = append(blocks[i], ciphertext[j])
		}
	}

	key := make([]byte, keysize)
	for idx, ciphertextBlock := range blocks {
		var bestScore float32 = math.MaxFloat32
		var bestKeyByte byte

		for keyByte := 0; keyByte < 256; keyByte++ {
			plaintext, _ := xor.SumRepeat(ciphertextBlock, []byte{byte(keyByte)})

			table1 := makeTable(bytes.NewReader(plaintext), 1)
			table2 := makeTable(bytes.NewReader(plaintext), 2)

			if score := corpusTable1.Compare(table1) + corpusTable2.Compare(table2); score < bestScore {
				bestScore, bestKeyByte = score, byte(keyByte)
			}
		}

		key[idx] = bestKeyByte

		fmt.Print(".")
	}
	fmt.Print("\n")

	bestPlaintext, _ := xor.SumRepeat(ciphertext, key)
	log.Printf("best key is %q producing:\n%s", string(key), bestPlaintext)
}
