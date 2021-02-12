package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"math/big"
)

type PrivKey struct {
	D, N *big.Int
}

type PubKey struct {
	E, N *big.Int
}

func Modexp(b, e, m *big.Int) *big.Int {
	// For simplicity panic here rather than returning an error.
	// Akin to how division by zero is handled.

	zero := big.NewInt(0)
	one := big.NewInt(1)
	two := big.NewInt(2)

	if m.Cmp(one) == -1 {
		log.Panic("Modexp: m < 1")
	} else if m.Cmp(one) == 0 {
		return zero
	}

	if e.Cmp(zero) == -1 {
		// TODO Add support for this
		log.Panic("Modexp: e < 0")
	} else if e.Cmp(zero) == 0 {
		return one
	} else if e.Cmp(one) == 0 {
		return new(big.Int).Mod(b, m)
	}

	c := big.NewInt(1)
	b2 := new(big.Int).Mod(b, m)
	e2 := new(big.Int).Set(e)

	// while e2 > 0
	for e2.Cmp(zero) == 1 {

		// if e2 % 2 == 1
		if new(big.Int).Mod(e2, two).Cmp(one) == 0 {
			// c = (c * b2) % m
			c.Mul(c, b2).Mod(c, m)
		}

		// e2 >>= 1
		e2.Rsh(e2, 1)

		// b2 = (b2 * b2) % m
		b2.Mul(b2, b2).Mod(b2, m)
	}

	return c
}

func Coprime(a, b *big.Int) bool {
	gcd := new(big.Int).GCD(nil, nil, a, b)
	return gcd.Cmp(big.NewInt(1)) == 0 
}

// Inverse multiplicative modulo
// Ie given a and m find b such that (a * b) mod m = 1
func Invmod(a, m *big.Int) *big.Int {
	// The inverse will not exist unless a and m are coprime
	if !Coprime(a, m) {
		log.Panic("Invmod: not coprime")
	}

	var rv *big.Int

	// Extended Euclidean algorithm which solves ax + by = gcd(a, b)
	{
		xi := big.NewInt(1)
		yi := big.NewInt(0)
		qi := big.NewInt(0)
		ri := new(big.Int).Add(new(big.Int).Mul(a, xi),
		                       new(big.Int).Mul(m, yi))

		xj := big.NewInt(0)
		yj := big.NewInt(1)
		qj := big.NewInt(0)
		rj := new(big.Int).Add(new(big.Int).Mul(a, xj),
		                       new(big.Int).Mul(m, yj))

		for {
			qk := new(big.Int).Div(ri, rj)
			rk := new(big.Int).Mod(ri, rj)
			xk := new(big.Int).Sub(xi, new(big.Int).Mul(qk, xj))
			yk := new(big.Int).Sub(yi, new(big.Int).Mul(qk, yj))

			if rk.Cmp(big.NewInt(0)) == 0 {
				break
			}

			qi, qj = qj, qk
			ri, rj = rj, rk
			xi, xj = xj, xk
			yi, yj = yj, yk
		}

		// If rj is one then a and m are coprime
		if rj.Cmp(big.NewInt(1)) != 0 {
			log.Panic("Invmod: rj != 0")
		}

		// rj = 1 = a*xj + m*yj => (a * xj) mod m = 1
		rv = xj

		// No-op to convince compiler qi is used
		qi.Add(qi, big.NewInt(0))
	}

	if rv.Cmp(big.NewInt(0)) < 0 {
		rv.Add(rv, m)
	}
	if rv.Cmp(big.NewInt(0)) < 0 {
		log.Panic("Invmod: rv < 0")
	}
	return rv
}

func KeyPair(bits uint) (*PrivKey, *PubKey) {
	e := big.NewInt(3)
	var n, d *big.Int

	for {
		privkey, err := rsa.GenerateKey(rand.Reader, int(bits))
		if err != nil {
			log.Panic(err)
		}

		if len(privkey.Primes) != 2 {
			log.Panic("more than 2 prime factors")
		}

		p, q := privkey.Primes[0], privkey.Primes[1]

		et := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)),
		                       new(big.Int).Sub(q, big.NewInt(1)))

		if !Coprime(et, e) {
			continue
		}

		n = new(big.Int).Mul(p, q)

		if false {
			d = new(big.Int).ModInverse(e, et)
		} else {
			d = Invmod(e, et)
		}
		break
	}

	return &PrivKey{ D: d, N: n}, &PubKey{ E: e, N: n }
}

func (k *PubKey) Encrypt(plaintext []byte) []byte {
	p := new(big.Int).SetBytes(plaintext)

	var c *big.Int
	if false {
		c = new(big.Int).Exp(p, k.E, k.N)
	} else {
		c = Modexp(p, k.E, k.N)
	}
	return c.Bytes()
}

func (k *PrivKey) Decrypt(ciphertext []byte) []byte {
	c := new(big.Int).SetBytes(ciphertext)

	var p *big.Int
	if false {
		p = new(big.Int).Exp(c, k.D, k.N)
	} else {
		p = Modexp(c, k.D, k.N)
	}
	return p.Bytes()
}
