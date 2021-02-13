package dsa

import (
	"crypto/dsa"
	"crypto/rand"
	"crypto/sha1"
	"log"
	"math/big"
)

type PrivKey struct {
	X *big.Int
}

type PubKey struct {
	P, Q, G, Y *big.Int
}

type Signature struct {
	R, S *big.Int
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

// Inverse multiplicative modulo
// Ie given a and m find b such that (a * b) mod m = 1
func Invmod(a, m *big.Int) *big.Int {
	coprime := func(a, b *big.Int) bool {
		gcd := new(big.Int).GCD(nil, nil, a, b)
		return gcd.Cmp(big.NewInt(1)) == 0 
	}

	// The inverse will not exist unless a and m are coprime
	if !coprime(a, m) {
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

func KeyPair(l, n uint) (*PrivKey, *PubKey) {
	var sizes dsa.ParameterSizes
	if l == 1024 && n == 160 {
		sizes = dsa.L1024N160
	} else if l == 2048 && n == 224 {
		sizes = dsa.L2048N224
	} else if l == 2048 && n == 256 {
		sizes = dsa.L2048N256
	} else if l == 3072 && n == 256 {
		sizes = dsa.L3072N256
	} else {
		log.Panic("invalid param sizes")
	}

	var params dsa.Parameters
	if err := dsa.GenerateParameters(&params, rand.Reader, sizes); err != nil {
		log.Panic(err)
	}

	x, err := rand.Int(rand.Reader, params.Q)
	if err != nil {
		log.Panic(err)
	}
	y := Modexp(params.G, x, params.P)

	return &PrivKey{ X: x }, &PubKey{ P: params.P, Q: params.Q, G: params.G, Y: y }
}

func KeyPairFixed(l, n uint) (*PrivKey, *PubKey) {
	if l != 1024 || n != 160 {
		log.Panic("l != 1024 || n != 160")
	}

	// q is an n-bit prime
	q := new(big.Int).SetBytes([]byte{0xf4, 0xf4, 0x7f, 0x5, 0x79, 0x4b, 0x25, 0x61, 0x74, 0xbb, 0xa6, 0xe9, 0xb3, 0x96, 0xa7, 0x70, 0x7e, 0x56, 0x3c, 0x5b})

	// p is an l-bit prime such that p-1 is a multiple of q
	p := new(big.Int).SetBytes([]byte{0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x89, 0xe1, 0x85, 0x52, 0x18, 0xa0, 0xe7, 0xda, 0xc3, 0x81, 0x36, 0xff, 0xaf, 0xa7, 0x2e, 0xda, 0x78, 0x59, 0xf2, 0x17, 0x1e, 0x25, 0xe6, 0x5e, 0xac, 0x69, 0x8c, 0x17, 0x2, 0x57, 0x8b, 0x7, 0xdc, 0x2a, 0x10, 0x76, 0xda, 0x24, 0x1c, 0x76, 0xc6, 0x2d, 0x37, 0x4d, 0x83, 0x89, 0xea, 0x5a, 0xef, 0xfd, 0x32, 0x26, 0xa0, 0x53, 0xc, 0xc5, 0x65, 0xf3, 0xbf, 0x6b, 0x50, 0x92, 0x91, 0x39, 0xeb, 0xea, 0xc0, 0x4f, 0x48, 0xc3, 0xc8, 0x4a, 0xfb, 0x79, 0x6d, 0x61, 0xe5, 0xa4, 0xf9, 0xa8, 0xfd, 0xa8, 0x12, 0xab, 0x59, 0x49, 0x42, 0x32, 0xc7, 0xd2, 0xb4, 0xde, 0xb5, 0xa, 0xa1, 0x8e, 0xe9, 0xe1, 0x32, 0xbf, 0xa8, 0x5a, 0xc4, 0x37, 0x4d, 0x7f, 0x90, 0x91, 0xab, 0xc3, 0xd0, 0x15, 0xef, 0xc8, 0x71, 0xa5, 0x84, 0x47, 0x1b, 0xb1})
	if new(big.Int).Mod(new(big.Int).Sub(p, big.NewInt(1)), q).Cmp(big.NewInt(0)) != 0 {
		log.Panic("p-1 % q != 0")
	}

	// g is a number such that its multiplicative order modulo p is q
	// Ie g = h ** ((p-1)/q) % p for an arbitrary h such that 1 < h < p-1 and g != 1
	g := new(big.Int).SetBytes([]byte{0x59, 0x58, 0xc9, 0xd3, 0x89, 0x8b, 0x22, 0x4b, 0x12, 0x67, 0x2c, 0xb, 0x98, 0xe0, 0x6c, 0x60, 0xdf, 0x92, 0x3c, 0xb8, 0xbc, 0x99, 0x9d, 0x11, 0x94, 0x58, 0xfe, 0xf5, 0x38, 0xb8, 0xfa, 0x40, 0x46, 0xc8, 0xdb, 0x53, 0x3, 0x9d, 0xb6, 0x20, 0xc0, 0x94, 0xc9, 0xfa, 0x7, 0x7e, 0xf3, 0x89, 0xb5, 0x32, 0x2a, 0x55, 0x99, 0x46, 0xa7, 0x19, 0x3, 0xf9, 0x90, 0xf1, 0xf7, 0xe0, 0xe0, 0x25, 0xe2, 0xd7, 0xf7, 0xcf, 0x49, 0x4a, 0xff, 0x1a, 0x4, 0x70, 0xf5, 0xb6, 0x4c, 0x36, 0xb6, 0x25, 0xa0, 0x97, 0xf1, 0x65, 0x1f, 0xe7, 0x75, 0x32, 0x35, 0x56, 0xfe, 0x0, 0xb3, 0x60, 0x8c, 0x88, 0x78, 0x92, 0x87, 0x84, 0x80, 0xe9, 0x90, 0x41, 0xbe, 0x60, 0x1a, 0x62, 0x16, 0x6c, 0xa6, 0x89, 0x4b, 0xdd, 0x41, 0xa7, 0x5, 0x4e, 0xc8, 0x9f, 0x75, 0x6b, 0xa9, 0xfc, 0x95, 0x30, 0x22, 0x91})

	x, err := rand.Int(rand.Reader, q)
	if err != nil {
		log.Panic(err)
	}
	y := Modexp(g, x, p)

	return &PrivKey{ X: x }, &PubKey{ P: p, Q: q, G: g, Y: y }
}

func KeyPairParams(p, q, g *big.Int) (*PrivKey, *PubKey) {
	// Purposefully omitting checks on the specified params

	x, err := rand.Int(rand.Reader, q)
	if err != nil {
		log.Panic(err)
	}
	y := Modexp(g, x, p)

	return &PrivKey{ X: x }, &PubKey{ P: p, Q: q, G: g, Y: y }
}

func Sign(msg []byte, privkey *PrivKey, pubkey *PubKey) (*Signature, *big.Int) {
	hb := sha1.Sum(msg)
	h := new(big.Int).SetBytes(hb[:])

	var k, r, s *big.Int
	for {
		for {
			var err error
			if k, err = rand.Int(rand.Reader, pubkey.Q); err != nil {
				log.Panic(err)
			}

			r = new(big.Int).Mod(Modexp(pubkey.G, k, pubkey.P), pubkey.Q)
			if r.Cmp(big.NewInt(0)) == 1 {
				break
			}
		}

		ki := Invmod(k, pubkey.Q)

		s = new(big.Int).Mod(new(big.Int).Mul(ki,
		                                      new(big.Int).Add(h,
		                                                       new(big.Int).Mul(privkey.X, r))),
		                     pubkey.Q)

		if s.Cmp(big.NewInt(0)) == 1 {
			break
		}
	}

	return &Signature{ R:r, S:s }, k
}

func (s *Signature) Verify(msg []byte, pubkey *PubKey) bool {
	if big.NewInt(0).Cmp(s.R) != -1 || s.R.Cmp(pubkey.Q) != -1 {
		return false
	}
	if big.NewInt(0).Cmp(s.S) != -1 || s.S.Cmp(pubkey.Q) != -1 {
		return false
	}

	hb := sha1.Sum(msg)
	h := new(big.Int).SetBytes(hb[:])

	w := Invmod(s.S, pubkey.Q)
	u1 := new(big.Int).Mod(new(big.Int).Mul(h, w), pubkey.Q)
	u2 := new(big.Int).Mod(new(big.Int).Mul(s.R, w), pubkey.Q)

	v := new(big.Int).Mod(new(big.Int).Mod(new(big.Int).Mul(Modexp(pubkey.G, u1, pubkey.P),
	                                                        Modexp(pubkey.Y, u2, pubkey.P)),
	                                       pubkey.P),
	                      pubkey.Q)

	return v.Cmp(s.R) == 0
}
