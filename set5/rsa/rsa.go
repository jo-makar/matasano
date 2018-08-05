package rsa

import (
    "../bigint"
    "math/big"
)

type Privkey struct {
    D, N *big.Int
}

type Pubkey struct {
    E, N *big.Int
}

func Keypair(bits int) (*Privkey, *Pubkey) {
    var n, d *big.Int
    e := big.NewInt(3)

    for {
        p, q := bigint.Primes(bits)

        et := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)),
                               new(big.Int).Sub(q, big.NewInt(1)))
        if !bigint.Coprime(et ,e) {
            continue
        }

        n = new(big.Int).Mul(p, q)
        d = bigint.Invmod(e, et)
        break
    }

    return &Privkey{D:d, N:n}, &Pubkey{E:e, N:n}
}

func (k *Pubkey) Encrypt(plaintext []byte) []byte {
    p := bigint.Frombytes(plaintext)
    return bigint.Modexp(p, k.E, k.N).Bytes()
}

func (k *Privkey) Decrypt(ciphertext []byte) []byte {
    c := bigint.Frombytes(ciphertext)
    return bigint.Modexp(c, k.D, k.N).Bytes()
}
