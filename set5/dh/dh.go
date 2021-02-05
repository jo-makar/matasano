package dh

import (
	"log"
	"math/big"
	"math/rand"
	"time"
)

type Dh struct {
	P, G *big.Int

	a *big.Int // Private key: random number modulo P
	A *big.Int // Public key: (G to the power of a) modulo P
}

func bigIntFromHex(h string) *big.Int {
	i := new(big.Int)
	if _, ok := i.SetString(h, 16); !ok {
		log.Panic("invalid hex")
	}
	return i
}

var NistP *big.Int = bigIntFromHex("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
                                   "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
                                   "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
                                   "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
                                   "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
                                   "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
                                   "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
                                   "fffffffffffff")
var NistG *big.Int = big.NewInt(2)

var bigIntRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
func bigIntRandIntn(n *big.Int) *big.Int {
	if big.NewInt(0).Cmp(n) != -1 {
		log.Panic("n <= 0")
	}
	return new(big.Int).Rand(bigIntRand, n)
}

func NewDhWithNist() *Dh {
	d := Dh{ P: NistP, G: NistG }
	d.a = bigIntRandIntn(d.P)
	d.A = new(big.Int).Exp(d.G, d.a, d.P)
	return &d
}

func NewDhWithParams(P, G *big.Int) *Dh {
	d := Dh{ P: P, G: G }
	d.a = bigIntRandIntn(d.P)
	d.A = new(big.Int).Exp(d.G, d.a, d.P)
	return &d
}

func (d *Dh) Session(e *Dh) *big.Int {
	// Disabled this check for the sake of a parameter injection attack demo
	//if d.P.Cmp(e.P) != 0 || d.G.Cmp(e.G) != 0 {
	//	log.Panic("dh: mismatched params")
	//}

	// Which is equal to ....Exp(d.A, e.a, d.P)
	return new(big.Int).Exp(e.A, d.a, d.P)
}
