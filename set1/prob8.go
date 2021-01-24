package main

import (
	"./hex"

	"bufio"
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"runtime"
)

func main() {
	//
	// Retrieve and decode the ciphertext
	//

	var path string
	if _, p, _, ok := runtime.Caller(0); !ok {
		log.Panic(errors.New("runtime.Caller() failed"))
	} else {
		path = filepath.Join(filepath.Dir(p), "prob8.txt")
	}

	file, err := os.Open(path)
	if err != nil {
		log.Panic(err)
	}
	defer file.Close()

	var ciphertexts [][]byte

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ciphertext, err := hex.Decode(scanner.Text())
		if err != nil {
			log.Panic(err)
		}

		if len(ciphertext) % 16 != 0 {
			log.Panic(errors.New("len(ciphertext) not multiple of blocksize"))
		}

		ciphertexts = append(ciphertexts, ciphertext)
	}
	if err := scanner.Err(); err != nil {
		log.Panic(err)
	}

	//
	// Identify the ciphertext with the most repeated blocks
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

	var bestRepeats int = -1
	var bestIndex int

	for idx, ciphertext := range ciphertexts {
		chunks := split(ciphertext, 16)

		var repeats int
		for i := 0; i < len(chunks)-1; i++ {
			for j := i; j < len(chunks); j++ {
				if bytes.Equal(chunks[i], chunks[j]) {
					repeats++
				}
			}
		}

		if repeats > bestRepeats {
			bestRepeats, bestIndex = repeats, idx
		}
	}

	suffix := func(n int) string {
		table := []string{"th", "st", "nd", "rd"}
		if n < len(table) {
			return table[n]
		} else {
			return "th"
		}
	}

	log.Printf("the %d%s ciphertext has %d repeated blocks", bestIndex+1, suffix(bestIndex+1), bestRepeats)
}
