package dh

import (
    "../bigint"
    "log"
    "math/big"
)

// Diffie-Hellman key exchange
type Dh struct {
    // P, G and Public are public info

    P *big.Int // prime
    G *big.Int // primitive root modulo P

    secret *big.Int // random number % P
    Public *big.Int // = (G**secret) % P
}

func NewDh() *Dh {
    d := new(Dh)

    d.P = bigint.Fromhex("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
                         "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
                         "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
                         "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
                         "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
                         "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
                         "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
                         "fffffffffffff")
    d.G = big.NewInt(2)

    d.secret = bigint.Randintn(d.P)
    d.Public = bigint.Modexp(d.G, d.secret, d.P)

    return d
}

func NewDh2(public *big.Int) *Dh {
    d := new(Dh)

    d.P = bigint.Fromhex("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
                         "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
                         "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
                         "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
                         "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
                         "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
                         "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
                         "fffffffffffff")
    d.G = big.NewInt(2)

    d.secret = bigint.Randintn(d.P)
    d.Public = public

    return d
}

func NewDh3(G *big.Int) *Dh {
    d := new(Dh)

    d.P = bigint.Fromhex("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
                         "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
                         "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
                         "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
                         "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
                         "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
                         "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
                         "fffffffffffff")

    d.G = G

    d.secret = bigint.Randintn(d.P)
    d.Public = bigint.Modexp(d.G, d.secret, d.P)

    return d
}

func (d *Dh) Session(e *Dh) *big.Int {
    if d.P.Cmp(e.P) != 0 || d.G.Cmp(e.G) != 0 {
        log.Fatal("dh: mismatched params")
    }

    return bigint.Modexp(e.Public, d.secret, d.P)
}
