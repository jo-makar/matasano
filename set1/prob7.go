package main

import (
	"./base64"

	"bufio"
	"crypto/aes"
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
		path = filepath.Join(filepath.Dir(p), "prob7.txt")
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

	if len(ciphertext) % 16 != 0 {
		log.Panic(errors.New("len(ciphertext) not multiple of blocksize"))
	}

	key := []byte("YELLOW SUBMARINE")
	if len(key) != 16 {
		log.Panic(errors.New("len(key) not equal to blocksize"))
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		log.Panic(err)
	}

	plaintext := make([]byte, len(ciphertext))

	for i := 0; i < len(ciphertext); i += 16 {
		cipher.Decrypt(plaintext[i:i+16], ciphertext[i:i+16])
	}

	fmt.Print(string(plaintext))
}
