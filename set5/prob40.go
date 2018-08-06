package main

import (
    "./bigint"
    "./rsa"
    "log"
    "math/big"
)

func main() {
    plaintext := []byte("hello world")

    pubkeys := make([]*rsa.Pubkey, 0)
    ciphertexts := make([]*big.Int, 0)
    for i:=0; i<3; i++ {
        _, pubkey := rsa.Keypair(256)
        ciphertext := pubkey.Encrypt(plaintext)

        pubkeys = append(pubkeys, pubkey)
        ciphertexts = append(ciphertexts, bigint.Frombytes(ciphertext))
    }

    // Apply the Chinese Remainder Theorem
    // Given x % n1 = a1
    //           ..
    //       x % nk = ak
    // with n1, .., nk being pairwise coprime
    // Then  x = sum( ai * N/ni * invmod(N/ni, ni) )
    // where N = n1 * .. * nk

    result := big.NewInt(0)

    ns0 := bigint.Mul(pubkeys[1].N, pubkeys[2].N)
    ns1 := bigint.Mul(pubkeys[0].N, pubkeys[2].N)
    ns2 := bigint.Mul(pubkeys[0].N, pubkeys[1].N)

    result = bigint.Add(result, bigint.Mul(bigint.Mul(ciphertexts[0], ns0),
                                          bigint.Invmod(ns0, pubkeys[0].N)))
    result = bigint.Add(result, bigint.Mul(bigint.Mul(ciphertexts[1], ns1),
                                          bigint.Invmod(ns1, pubkeys[1].N)))
    result = bigint.Add(result, bigint.Mul(bigint.Mul(ciphertexts[2], ns2),
                                          bigint.Invmod(ns2, pubkeys[2].N)))

    result = bigint.Mod(result, bigint.Mul(bigint.Mul(pubkeys[0].N, pubkeys[1].N), pubkeys[2].N))

    // The math/big package doesn't provide a root func so show equivalence by cubing the plaintext.
    // (However see https://rosettacode.org/wiki/Nth_root#Go if it is needed later)

    if result.Cmp(bigint.Pow(bigint.Frombytes(plaintext), big.NewInt(3))) != 0 {
        log.Fatal("result != plaintext**3")
    }
}
