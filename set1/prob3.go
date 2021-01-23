package main

import (
	"./hex"
	"./score"
	"./xor"

	"bytes"
	"errors"
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

	var path string
	if _, p, _, ok := runtime.Caller(0); !ok {
		log.Panic(errors.New("runtime.Caller() failed"))
	} else {
		path = filepath.Join(filepath.Dir(p), "The Brothers Karamazov.txt")
	}

	file, err := os.Open(path)
	if err != nil {
		log.Panic(err)
	}
	defer file.Close()

	makeTable := func(reader io.Reader, n uint) *score.Table {
		table, err := score.NewTable(reader, n)
		if err != nil {
			log.Panic(err)
		}
		return table
	}

	table1 := makeTable(file, 1)
	if _, err := file.Seek(0, 0); err != nil {
		log.Panic(err)
	}
	table2 := makeTable(file, 2)

	//
	// Identify the most-likely key based on occurrence tables
	//

	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	ciphertext, err := hex.Decode(input)
	if err != nil {
		log.Panic(err)
	}

	var bestScore float32 = math.MaxFloat32
	var bestKey byte

	for key := 0; key < 256; key++ {
		plaintext, _ := xor.SumRepeat(ciphertext, []byte{byte(key)})

		t1 := makeTable(bytes.NewReader(plaintext), 1)
		t2 := makeTable(bytes.NewReader(plaintext), 2)

		if score := table1.Compare(t1) + table2.Compare(t2); score < bestScore {
			bestScore, bestKey = score, byte(key)
		}
	}

	bestPlaintext, _ := xor.SumRepeat(ciphertext, []byte{byte(bestKey)})
	log.Printf("best byte is %#x producing %q", bestKey, bestPlaintext)
}
