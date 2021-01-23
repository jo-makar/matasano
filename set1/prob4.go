package main

import (
	"./hex"
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

	table1 := makeTable(corpusFile, 1)
	if _, err := corpusFile.Seek(0, 0); err != nil {
		log.Panic(err)
	}
	table2 := makeTable(corpusFile, 2)

	//
	// Identify the most-likely key and ciphertext pair
	//

	var ciphertexts []([]byte)

	inputFile, err := os.Open(filepath.Join(basePath, "prob4.txt"))
	if err != nil {
		log.Panic(err)
	}
	defer inputFile.Close()

	scanner := bufio.NewScanner(inputFile)
	for scanner.Scan() {
		ciphertext, err := hex.Decode(scanner.Text())
		if err != nil {
			log.Panic(err)
		}

		ciphertexts = append(ciphertexts, ciphertext)
	}
	if err := scanner.Err(); err != nil {
		log.Panic(err)
	}

	var bestScore float32 = math.MaxFloat32
	var bestCiphertextIdx int
	var bestKey byte

	for idx, ciphertext := range ciphertexts {
		for key := 0; key < 256; key++ {
			plaintext, _ := xor.SumRepeat(ciphertext, []byte{byte(key)})

			t1 := makeTable(bytes.NewReader(plaintext), 1)
			t2 := makeTable(bytes.NewReader(plaintext), 1)

			if score := table1.Compare(t1) + table2.Compare(t2); score < bestScore {
				bestScore, bestCiphertextIdx, bestKey = score, idx, byte(key)
			}
		}

		fmt.Print(".")
	}
	fmt.Print("\n")

	suffix := func(n int) string {
		table := []string{"th", "st", "nd", "rd"}
		if n < len(table) {
			return table[n]
		} else {
			return "th"
		}
	}

	bestPlaintext, _ := xor.SumRepeat(ciphertexts[bestCiphertextIdx], []byte{byte(bestKey)})
	log.Printf("best byte is %#x against the %d%s ciphertext producing %q",
		   bestKey, bestCiphertextIdx, suffix(bestCiphertextIdx), bestPlaintext)
}
