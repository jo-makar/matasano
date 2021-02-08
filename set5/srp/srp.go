package srp

import (
	"bytes"
	"crypto/sha256"
	"log"
	"math/big"
	"math/rand"
	"time"
)

type Client struct {
	I, p string // Email, password

	a *big.Int // Private key: random number modulo N
	A *big.Int // Public key: (G to the power of a) modulo N
}

type Server struct {
	I, p string // Email, password

	Salt []byte
	v    *big.Int // (G to the power of sha256(salt || password)) modulo N
	b    *big.Int // Private key: random number modulo N
	B    *big.Int // Public key: ((G to the power of b) modulo N) plus K times v
}

func bigIntFromHex(h string) *big.Int {
	i := new(big.Int)
	if _, ok := i.SetString(h, 16); !ok {
		log.Panic("invalid hex")
	}
	return i
}

var NistN *big.Int = bigIntFromHex("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
                                   "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
                                   "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
                                   "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
                                   "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
                                   "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
                                   "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
                                   "fffffffffffff")
var G = big.NewInt(2)
var K = big.NewInt(3)

var pkgRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

func bigIntRandIntn(n *big.Int) *big.Int {
	if big.NewInt(0).Cmp(n) != -1 {
		log.Panic("n <= 0")
	}
	return new(big.Int).Rand(pkgRand, n)
}

func randBytes(n uint) []byte {
	b := make([]byte, n)
	pkgRand.Read(b)
	return b
}

func bigIntFromBytes(b []byte) *big.Int {
	i := new(big.Int)
	return i.SetBytes(b)
}

// The math/big.Int.Exp implementation performance is insufficient
func bigIntModExp(b, e, m *big.Int) *big.Int {
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

func NewClient(i, p string) *Client {
	c := Client{ I: i, p: p }
	c.a = bigIntRandIntn(NistN)
	c.A = new(big.Int).Exp(G, c.a, NistN)
	return &c
}

func NewServer(i, p string) *Server {
	s := Server{ I: i, p: p }
	s.Salt = randBytes(8)

	var buf bytes.Buffer
	buf.Write(s.Salt)
	buf.Write([]byte(s.p))
	xH := sha256.Sum256(buf.Bytes())
	x := bigIntFromBytes(xH[:])
	s.v = new(big.Int).Exp(G, x, NistN)

	s.b = bigIntRandIntn(NistN)
	s.B = new(big.Int).Add(new(big.Int).Exp(G, s.b, NistN),
	                       new(big.Int).Mul(K, s.v))

	return &s
}

func HmacSha256(key, msg []byte) [sha256.Size]byte {
	keyPrime := make([]byte, len(key))
	copy(keyPrime, key)

	if len(keyPrime) > sha256.BlockSize {
		s := sha256.Sum256(keyPrime)
		keyPrime = s[:]
	}
	if len(keyPrime) < sha256.BlockSize {
		keyPrime = append(keyPrime, make([]byte, sha256.BlockSize-len(keyPrime))...)
	}

	paddingBlock := func(b byte) [sha256.BlockSize]byte {
		var block [sha256.BlockSize]byte
		for i := 0; i < len(block); i++ {
			block[i] = b
		}
		return block
	}

	outerPad := paddingBlock(0x5c)
	innerPad := paddingBlock(0x36)

	outerBlock := make([]byte, sha256.BlockSize)
	for i := 0; i < len(outerBlock); i++ {
		outerBlock[i] = keyPrime[i] ^ outerPad[i]
	}

	innerBlock := make([]byte, sha256.BlockSize)
	for i := 0; i < len(innerBlock); i++ {
		innerBlock[i] = keyPrime[i] ^ innerPad[i]
	}
	innerBlock = append(innerBlock, msg...)

	s := sha256.Sum256(innerBlock)
	outerBlock = append(outerBlock, s[:]...)
	return sha256.Sum256(outerBlock)
}

func (s *Server) VerifyClient(c *Client) bool {
	if s.I != c.I {
		log.Panic("srp: I mismatch")
	}

	var buf bytes.Buffer
	buf.Write(c.A.Bytes())
	buf.Write(s.B.Bytes())
	uH := sha256.Sum256(buf.Bytes())
	u := bigIntFromBytes(uH[:])

	//
	// Client HMAC
	//

	var clientHmac [sha256.Size]byte
	{
		var buf bytes.Buffer
		buf.Write(s.Salt)
		buf.Write([]byte(c.p))
		xH := sha256.Sum256(buf.Bytes())
		x := bigIntFromBytes(xH[:])

		var S *big.Int
		if false {
			base := new(big.Int).Sub(s.B, new(big.Int).Mul(new(big.Int).Exp(G, x, nil), K))
			exp := new(big.Int).Add(c.a, new(big.Int).Mul(u, x))
			S = new(big.Int).Exp(base, exp, NistN)
		} else {
			// Simplified the given formula for S (original too slow to calculate)
			// S = ((((B % N) - ((k % N) * (g**x % N)) % N) % N) ** (a + u * x)) % N

			// base = ((B % N) - ((k % N) * (g**x % N)) % N) % N
			b1 := new(big.Int).Exp(G, x, NistN)
			b2 := new(big.Int).Mul(new(big.Int).Mod(K, NistN), b1)
			b3 := new(big.Int).Sub(new(big.Int).Mod(s.B, NistN),
			                       new(big.Int).Mod(b2, NistN))
			base := new(big.Int).Mod(b3, NistN)

			exp := new(big.Int).Add(c.a, new(big.Int).Mul(u, x))
			S = new(big.Int).Exp(base, exp, NistN)
		}

		K := sha256.Sum256(S.Bytes())
		clientHmac = HmacSha256(K[:], s.Salt)
	}

	//
	// Server HMAC
	//

	var serverHmac [sha256.Size]byte
	{
		var S *big.Int
		if false {
			S = new(big.Int).Mul(c.A, new(big.Int).Exp(s.v, u, nil))
		} else {
			// Simplified the given formula for S (original too slow to calculate)
			// S = ((((A % N) * (v**u % N)) % N) ** b) % N

			// base = ((A % N) * (v**u % N)) % N
			b1 := new(big.Int).Exp(s.v, u, NistN)
			b2 := new(big.Int).Mul(new(big.Int).Mod(c.A, NistN), b1)
			base := new(big.Int).Mod(b2, NistN)

			S = new(big.Int).Exp(base, s.b, NistN)
		}

		K := sha256.Sum256(S.Bytes())
		serverHmac = HmacSha256(K[:], s.Salt)
	}

	return bytes.Equal(clientHmac[:], serverHmac[:])
}

func (s *Server) VerifyHmac(clientA *big.Int, clientHmac []byte) bool {
	var buf bytes.Buffer
	buf.Write(clientA.Bytes())
	buf.Write(s.B.Bytes())
	uH := sha256.Sum256(buf.Bytes())
	u := bigIntFromBytes(uH[:])

	//
	// Server HMAC
	//

	var serverHmac [sha256.Size]byte
	{
		var S *big.Int
		if false {
			S = new(big.Int).Mul(clientA, new(big.Int).Exp(s.v, u, nil))
		} else {
			// Simplified the given formula for S (original too slow to calculate)
			// S = ((((A % N) * (v**u % N)) % N) ** b) % N

			// base = ((A % N) * (v**u % N)) % N
			b1 := new(big.Int).Exp(s.v, u, NistN)
			b2 := new(big.Int).Mul(new(big.Int).Mod(clientA, NistN), b1)
			base := new(big.Int).Mod(b2, NistN)

			S = new(big.Int).Exp(base, s.b, NistN)
		}

		K := sha256.Sum256(S.Bytes())
		serverHmac = HmacSha256(K[:], s.Salt)
	}

	return bytes.Equal(clientHmac, serverHmac[:])
}
