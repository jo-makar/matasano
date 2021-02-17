package main

import (
	"../set5/rsa"

	"bytes"
	"log"
	"math/big"
)

func main() {
	const bits = 768
	var privkey *rsa.PrivKey
	var pubkey *rsa.PubKey

	if false {
		privkey, pubkey = rsa.KeyPair(bits)
	} else {
		n, _ := new(big.Int).SetString("99c2ed2ba72501505be3a06b1f394f6344e13e19a8a10212bd76c3a8aa5c819aee9b1ffddae5ac26bafa5a2a397409268fb826796b08fe122351e17308585495fc2b45b68bd542d47a8a8a0021a38b78c9b56b6be4c32395635bafe318113d6f", 16)
		d, _ := new(big.Int).SetString("6681f3726f6e00e03d426af214d0df978340d4111b160161d3a4827071930111f4676aa93c991d6f275191717ba2b0c357262158afa1cf25a3cd2b32e67d369cbaa523fbbc98714293044983dce8e050492dc5df092e0a3ee7d79e207374c40b", 16)
		privkey = &rsa.PrivKey{ D: d, N: new(big.Int).Set(n) }
		pubkey = &rsa.PubKey{ E: new(big.Int).Set(big.NewInt(3)), N: new(big.Int).Set(n) }
	}

	add := func(a, b *big.Int) *big.Int { return new(big.Int).Add(a, b) }
	sub := func(a, b *big.Int) *big.Int { return new(big.Int).Sub(a, b) } 
	mul := func(a, b *big.Int) *big.Int { return new(big.Int).Mul(a, b) }

	/*
	divCeil := func(a, b *big.Int) *big.Int {
		q, m := new(big.Int), new(big.Int)
		q.DivMod(a, b, m)
		if m.Cmp(big.NewInt(0)) == 1 {
			q.Add(q, big.NewInt(1))
		}
		return q
	}
	*/

	divFloor := func(a, b *big.Int) *big.Int { return new(big.Int).Div(a, b) }
	div := divFloor

	pow := func(a, b *big.Int) *big.Int { return new(big.Int).Exp(a, b, nil) }

	max := func(a, b *big.Int) *big.Int {
		if a.Cmp(b) >= 0 {
			return a
		} else {
			return b
		}
	}

	min := func(a, b *big.Int) *big.Int {
		if a.Cmp(b) <= 0 {
			return a
		} else {
			return b
		}
	}

	one := big.NewInt(1)
	two := big.NewInt(2)
	three := big.NewInt(3)

	// 2**(8*(k-1)) <= n < 2**(8*k) where k = bits/8
	if pow(two, big.NewInt(8 * (bits/8 - 1))).Cmp(pubkey.N) == 1 {
		log.Panic("2**(8*(k-1)) > n")
	}
	if pubkey.N.Cmp(pow(two, big.NewInt(8 * bits/8))) >= 0 {
		log.Panic("n >= 2**(8*k)")
	}

	oracle := func(ciphertext []byte) bool {
		plaintext := privkey.Decrypt(ciphertext)

		// This is needed because the padding starts with a zero byte
		// and the conversion between bytes and math/big.Int is big-endian
		if len(plaintext) < bits / 8 {
			plaintext2 := make([]byte, bits / 8)
			n := bits/8 - len(plaintext)
			copy(plaintext2[n:n+len(plaintext)], plaintext[0:len(plaintext)])
			plaintext = plaintext2
		}

		// This isn't fully checking PKCS#1 padding it should verify:
		//     00 02 <padding string> 00 <data block>
		// But it is sufficient for this attack demonstration.

		return plaintext[0] == 0x00 && plaintext[1] == 0x02
	}

	// This isn't exactly PKCS#1 padding it should be:
	//     00 02 <padding string> 00 <data block>
	// But it is sufficient for this attack demonstration.

	rawPlaintext := []byte("kick it, CC")
	plaintext := []byte{0x00, 0x02}
	plaintext = append(plaintext, make([]byte, bits/8 - len(plaintext) - len(rawPlaintext))...)
	plaintext = append(plaintext, rawPlaintext...)
	if len(plaintext) != bits / 8 {
		log.Printf("padded plaintext length incorrect")
	}

	ciphertext := pubkey.Encrypt(plaintext)

	B := pow(two, big.NewInt(8 * (bits/8 - 2)))
	c0 := new(big.Int).SetBytes(ciphertext)

	var Mi [][2]*big.Int
	Mi = append(Mi, [2]*big.Int{ mul(two, B), sub(mul(three, B), one) })

	//
	// Step 2a - Starting the search
	//

	s1 := div(sub(add(pubkey.N, mul(three, B)), one), mul(three, B))

	for i := 0; ; i++ {
		if oracle(mul(c0, rsa.Modexp(s1, pubkey.E, pubkey.N)).Bytes()) {
			break
		}
		s1.Add(s1, one)
	}

	log.Printf("s1 = %v", s1)

	si := s1

	for {
		//
		// Step 3
		//

		Mi1 := Mi
		Mi = make([][2]*big.Int, 0)

		for _, M := range Mi1 {
			a, b := M[0], M[1]

			rLower := div(add(sub(mul(a, si), mul(three, B)), pubkey.N), pubkey.N)
			rUpper := div(sub(mul(b, si), mul(two, B)), pubkey.N)

			/*
			if rLower.Cmp(rUpper) == 1 {
				log.Panic("rLower > rUpper")
			}
			*/

			for r := new(big.Int).Set(rLower); r.Cmp(rUpper) <= 0; r.Add(r, one) {

				a2 := max(a, div(sub(add(add(mul(two, B), mul(r, pubkey.N)), si), one), si))
				b2 := min(b, div(add(sub(mul(three, B), one), mul(r, pubkey.N)), si))

				if b2.Cmp(a2) == -1 {
					continue
				}

				Mi = append(Mi, [2]*big.Int{ a2, b2 })
			}
		}

		if len(Mi) == 0 {
			log.Panic("zero ranges")
		}

		if len(Mi) == 1 && Mi[0][0].Cmp(Mi[0][1]) == 0 {
			break
		}

		//
		// Step 2b - Searching with more than one interval left
		//

		if len(Mi) > 1 {
			for {
				si.Add(si, one)
				if oracle(mul(c0, rsa.Modexp(si, pubkey.E, pubkey.N)).Bytes()) {
					break
				}
			}
		}

		//
		// Step 2c - Searching with one interval left
		//

		if len(Mi) == 1 {
			a, b := Mi[0][0], Mi[0][1]

			ri := div(sub(add(mul(two, sub(mul(b, si), mul(two, B))), pubkey.N), one), pubkey.N)

			step2c:
			for {
				siLower := div(sub(add(add(mul(two, B), mul(ri, pubkey.N)), b), one), b)
				siUpper := div(sub(add(add(mul(three, B), mul(ri, pubkey.N)), a), one), a)

				if siLower.Cmp(siUpper) == 1 {
					log.Panic("siLower > siUpper")
				}

				for siTest := new(big.Int).Set(siLower); siTest.Cmp(siUpper) == -1; siTest.Add(siTest, one) {
					if oracle(mul(c0, rsa.Modexp(siTest, pubkey.E, pubkey.N)).Bytes()) {
						si = new(big.Int).Set(siTest)
						break step2c
					}
				}

				ri.Add(ri, one)
			}
		}

		log.Printf("si = %v", si)
	}

	//
	// Step 4 - Computing the solution
	//

	a := Mi[0][0]
	m := new(big.Int).Mod(a, pubkey.N).Bytes()

	// This is needed because the padding starts with a zero byte
	// and the conversion between bytes and math/big.Int is big-endian
	if len(m) < bits / 8 {
		m2 := make([]byte, bits / 8)
		n := bits/8 - len(m)
		copy(m2[n:n+len(m)], m[0:len(m)])
		m = m2
	}

	if !bytes.Equal(m, plaintext) {
		log.Panic("match not found")
	}
}
