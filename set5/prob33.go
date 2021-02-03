package main

import (
	"log"
	"math/big"
	"math/rand"
	"time"
)

func main() {
	bigIntFromHex := func(h string) *big.Int {
		i := new(big.Int)
		if _, ok := i.SetString(h, 16); !ok {
			log.Panic("invalid hex")
		}
		return i
	}

	randBigIntRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	randBigInt := func(n *big.Int) *big.Int {
		if big.NewInt(0).Cmp(n) != -1 {
			log.Panic("n <= 0")
		}
		return new(big.Int).Rand(randBigIntRand, n)
	}

	// The math/big.Int.Exp implementation seems sufficient including the following for reference
	
	bigIntModExp := func(b, e, m *big.Int) *big.Int {
		// For simplicity panic here rather than returning an error.
		// Akin to how division by zero is handled.

		zero := big.NewInt(0)
		one := big.NewInt(1)
		two := big.NewInt(2)

		if m.Cmp(one) == -1 {
			log.Panic("modExp: m < 1")
		} else if m.Cmp(one) == 0 {
			return zero
		}

		if e.Cmp(zero) == -1 {
			// TODO Add support for this
			log.Panic("modExp: e < 0")
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

	modExp := func(b, e, m *big.Int) *big.Int {
		if false {
			return new(big.Int).Exp(b, e, m)
		} else {
			return bigIntModExp(b, e, m)
		}
	}

	p := bigIntFromHex("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
	                   "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
	                   "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
	                   "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
	                   "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
	                   "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
	                   "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
	                   "fffffffffffff")
	g := big.NewInt(2)

	a := randBigInt(p)
	A := modExp(g, a, p)
	b := randBigInt(p)
	B := modExp(g, b, p)

	s1 := modExp(B, a, p)
	s2 := modExp(A, b, p)
	if s1.Cmp(s2) != 0 {
		log.Panic("s1 != s2")
	}
}
