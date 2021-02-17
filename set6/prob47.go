package main

import (
	"../set5/rsa"

	"bytes"
	"log"
	"math/big"
)

func main() {
	const bits = 256
	privkey, pubkey := rsa.KeyPair(bits)

	// TODO Using e=3 causes issues si boundary issues, investigate further.
	//      There are modifications to the calculations implemented in prob48.go that resolve this.
	if true {
		n, _ := new(big.Int).SetString("32148684684676556405470307304212155563108038575817858708524559838688846782883", 10)
		privkey.D.SetString("17465275638390895437086910008989877270185252992890772042131376337850261504993", 10)
		privkey.N.Set(n)
		pubkey.E.Set(big.NewInt(65537))
		pubkey.N.Set(n)
	}

	// 2**(8*(k-1)) <= n < 2**(8*k) where k = bits/8
	if new(big.Int).Exp(big.NewInt(2), big.NewInt(8 * (bits/8 - 1)), nil).Cmp(pubkey.N) == 1 {
		log.Panic("2**(8*(k-1)) > n")
	}
	if pubkey.N.Cmp(new(big.Int).Exp(big.NewInt(2), big.NewInt(8 * bits/8), nil)) >= 0 {
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

	divCeil := func(a, b *big.Int) *big.Int {
		q, m := new(big.Int), new(big.Int)
		q.DivMod(a, b, m)
		if m.Cmp(big.NewInt(0)) == 1 {
			q.Add(q, big.NewInt(1))
		}
		return q
	}

	divFloor := func(a, b *big.Int) *big.Int {
		return new(big.Int).Div(a, b)
	}

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

	B := new(big.Int).Exp(big.NewInt(2), big.NewInt(8 * (bits/8 - 2)), nil)
	c0 := new(big.Int).SetBytes(ciphertext)

	var Mi [][2]*big.Int
	Mi = append(Mi, [2]*big.Int{ new(big.Int).Mul(big.NewInt(2), B),
	                             new(big.Int).Sub(new(big.Int).Mul(big.NewInt(3), B), big.NewInt(1)) })

	//
	// Step 2a - Starting the search
	//

	s1 := divCeil(pubkey.N, new(big.Int).Mul(big.NewInt(3), B))
	for i := 0; ; i++ {
		if oracle(new(big.Int).Mul(c0, rsa.Modexp(s1, pubkey.E, pubkey.N)).Bytes()) {
			break
		}
		s1.Add(s1, big.NewInt(1))
	}

	log.Printf("s1 = %v", s1)

	si1 := s1
	var si *big.Int

	for {
		//
		// Step 2c - Searching with one interval left
		//

		if len(Mi) != 1 {
			log.Panic("len(Mi) != 1")
		}

		a, b := Mi[0][0], Mi[0][1]

		ri := new(big.Int).Mul(big.NewInt(2), divFloor(new(big.Int).Sub(new(big.Int).Mul(b, si1),
		                                                                new(big.Int).Mul(big.NewInt(2), B)),
		                                               pubkey.N))

		step2c:
		for {
			siLower := divFloor(new(big.Int).Add(new(big.Int).Mul(big.NewInt(2), B),
			                                     new(big.Int).Mul(ri, pubkey.N)),
			                    b)

			siUpper := divCeil(new(big.Int).Add(new(big.Int).Mul(big.NewInt(3), B),
			                                    new(big.Int).Mul(ri, pubkey.N)),
			                   a)

			if siLower.Cmp(siUpper) == 1 {
				log.Panic("siLower > siUpper")
			}

			for siTest := new(big.Int).Set(siLower); siTest.Cmp(siUpper) == -1; siTest.Add(siTest, big.NewInt(1)) {
				if oracle(new(big.Int).Mul(c0, rsa.Modexp(siTest, pubkey.E, pubkey.N)).Bytes()) {
					si = new(big.Int).Set(siTest)
					break step2c
				}
			}

			ri.Add(ri, big.NewInt(1))
		}

		//
		// Step 3 - Narrowing the set of solutions
		//

		Mi[0][0] = max(a, divCeil(new(big.Int).Add(new(big.Int).Mul(big.NewInt(2), B),
		                                           new(big.Int).Mul(ri, pubkey.N)),
		                          si))

		if a.Cmp(Mi[0][0]) == 1 {
			log.Panic("Mi-1[0][0] > Mi[0][0]")
		}

		Mi[0][1] = min(b, divFloor(new(big.Int).Add(new(big.Int).Sub(new(big.Int).Mul(big.NewInt(3), B),
		                                                                              big.NewInt(1)),
		                                            new(big.Int).Mul(ri, pubkey.N)),
		                           si))

		if b.Cmp(Mi[0][1]) == -1 {
			log.Panic("Mi-1[0][1] < Mi[0][1]")
		}

		log.Printf("si = %v", si)

		si1 = new(big.Int).Set(si)

		if len(Mi) == 1 && Mi[0][0].Cmp(Mi[0][1]) == 0 {
			break
		}
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
