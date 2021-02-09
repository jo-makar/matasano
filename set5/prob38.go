package main

import (
	"./ssrp"

	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
)

func main() {
	i, p := "user@host", "secret"
	if !ssrp.NewServer(i, p).VerifyClient(ssrp.NewClient(i, p)) {
		log.Panic("ssrp verify failed")
	}

	//
	// Offline dictionary MITM attack
	//

	// Arbitrarily set B = G and U = 1 to simplify S:
	//     S = (B ** (a + Ux)) % N
	//       = ...
	//       = (A * (g**x % N)) % N

	client := ssrp.NewClient(i, p)
	serverB, serverU, serverSalt := ssrp.G, big.NewInt(1), make([]byte, 8)
	targetHmac := client.Hmac(serverB, serverU, serverSalt)

	var file *os.File
	if _, p, _, ok := runtime.Caller(0); !ok {
		log.Panic(errors.New("runtime.Caller() failed"))
	} else {
		var err error
		file, err = os.Open(filepath.Join(filepath.Dir(p), "words.txt"))
		if err != nil {
			log.Panic(err)
		}
		defer file.Close()
	}

	found := false
	count := 0

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := scanner.Text()

		var buf bytes.Buffer
		buf.Write(serverSalt)
		buf.Write([]byte(word))
		xH := sha256.Sum256(buf.Bytes())
		x := new(big.Int).SetBytes(xH[:])

		S := new(big.Int).Mod(new(big.Int).Mul(client.A,
		                                       new(big.Int).Exp(ssrp.G, x, ssrp.NistN)),
		                      ssrp.NistN)

		K := sha256.Sum256(S.Bytes())
		hmac := ssrp.HmacSha256(K[:], serverSalt)

		if bytes.Equal(hmac[:], targetHmac[:]) {
			fmt.Printf("\n")
			log.Printf("found password: %q", word)
			found = true
			break
		}

		count++
		if count % 1000 == 0 {
			fmt.Printf(".")
		}
	}
	if err := scanner.Err(); err != nil {
		log.Panic(err)
	}

	if !found {
		log.Panic(errors.New("password not found"))
	}
}
