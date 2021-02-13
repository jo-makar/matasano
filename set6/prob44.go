package main

import (
	"./dsa"

	"bufio"
	"bytes"
	"crypto/sha1"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {
	//
	// Parse the input file
	//

	var file *os.File
	if _, p, _, ok := runtime.Caller(0); !ok {
		log.Panic("runtime.Caller() failed")
	} else {
		var err error
		file, err = os.Open(filepath.Join(filepath.Dir(p), "prob44.txt"))
		if err != nil {
			log.Panic(err)
		}
		defer file.Close()
	}

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Panic(err)
	}

	if len(lines) == 0 || len(lines) % 4 != 0 {
		log.Panic("invalid line count")
	}

	type Input struct {
		msg     []byte
		s, r, m *big.Int
	}

	var inputs []Input

	stringToBigInt := func(s string, base int) *big.Int {
		z, ok := new(big.Int).SetString(s, base)
		if !ok {
			log.Panic("input s value")
		}
		return z
	}

	for i := 0; i < len(lines); i += 4 {
		if !strings.HasPrefix(lines[i], "msg: ") {
			log.Panic("invalid msg input")
		}
		msg := []byte(lines[i][5:])

		if !strings.HasPrefix(lines[i+1], "s: ") {
			log.Panic("invalid s input")
		}
		s := stringToBigInt(lines[i+1][3:], 10)

		if !strings.HasPrefix(lines[i+2], "r: ") {
			log.Panic("invalid r input")
		}
		r := stringToBigInt(lines[i+2][3:], 10)

		if !strings.HasPrefix(lines[i+3], "m: ") {
			log.Panic("invalid m input")
		}
		m := stringToBigInt(lines[i+3][3:], 16)

		inputs = append(inputs, Input{ msg: msg, s: s, r: r, m: m })
	}

	//
	// Identify the input pair with the repeated k
	// And use it to calculate the private key
	//

	//p := stringToBigInt("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16)
	q := stringToBigInt("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
	//g := stringToBigInt("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16)

	target := []byte{0xca, 0x8f, 0x6f, 0x7c, 0x66, 0xfa, 0x36, 0x2d, 0x40, 0x76, 0x0d, 0x13, 0x5b, 0x76, 0x3e, 0xb8, 0x52, 0x7d, 0x3d, 0x52}
	found := false
	loops:
	for i := 0; i < len(inputs)-1; i++ {
		for j := i+1; j < len(inputs); j++ {
			// r = (g**k % p) % q
			if inputs[i].r.Cmp(inputs[j].r) == 0 {

				k := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Sub(inputs[i].m, inputs[j].m),
				                                       dsa.Invmod(new(big.Int).Sub(inputs[i].s, inputs[j].s), q)),
				                      q)

				hb := sha1.Sum(inputs[i].msg)
				h := new(big.Int).SetBytes(hb[:])

				ri := dsa.Invmod(inputs[i].r, q)
				x := new(big.Int).Mod(new(big.Int).Mul(ri,
				                                       new(big.Int).Sub(new(big.Int).Mul(inputs[i].s, k),
				                                                            h)),
				                      q)

				hx := sha1.Sum([]byte(x.Text(16)))
				if bytes.Equal(hx[:], target) {
					log.Printf("privkey x = %v", x.Text(16))
					found = true
					break loops
				}
			}
		}
	}
	if !found {
		log.Panic("pair not found")
	}
}
