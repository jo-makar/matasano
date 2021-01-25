package main

import (
	"../set1/base64"
	"./aes"

	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
)

func main() {
	var path string
	if _, p, _, ok := runtime.Caller(0); !ok {
		log.Panic(errors.New("runtime.Caller() failed"))
	} else {
		path = filepath.Join(filepath.Dir(p), "../set1/prob7.txt")
	}

	file, err := os.Open(path)
	if err != nil {
		log.Panic(err)
	}
	defer file.Close()

	var ciphertext []byte

	scanner := bufio.NewScanner(file)
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

	key := []byte("YELLOW SUBMARINE")

	plaintext, err := aes.EcbDecrypt(ciphertext, key)
	if  err != nil {
		log.Panic(err)
	}

	fmt.Print(string(plaintext))
}
