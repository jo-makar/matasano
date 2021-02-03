package main

import (
    "./bigint"
    "./dh"
    "../set2/aes"
    "../set4/rand"
    "../set4/sha1"
    "bytes"
    "errors"
    "fmt"
    "log"
    "math/big"
)

func main() {
    P := bigint.Fromhex("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
                        "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
                        "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
                        "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
                        "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
                        "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
                        "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
                        "fffffffffffff")

    plaintext := []byte("Yellow submarine")

    // Man-in-the-Middle with g = 1
    // => Public = 1^secret % P => 1 for all secret
    // => Session = 1^secret % P => 1
    {
        A := dh.NewDh3(big.NewInt(1))
        B := dh.NewDh3(big.NewInt(1))

        s2 := sha1.Sum([]byte{1})
        key := s2[:16]

        ciphertext := send(A, B, plaintext)

        iv := ciphertext[len(ciphertext)-16:]
        plaintext2, err := aes.Cbcdecrypt(ciphertext[:len(ciphertext)-16], key, iv)
        if err != nil {
            log.Fatal(err)
        }

        fmt.Printf("intercepted: %v, %q\n", plaintext2, string(plaintext2))

        ciphertext2 := echo(A, B, ciphertext)
        match := verify(A, B, plaintext, ciphertext2)
        if !match {
            log.Fatal(fmt.Sprintf("verify() failed"))
        }
    }

    // Man-in-the-Middle with g = p
    // => Public = P^secret % P => 0 for all secret (except secret = 0)
    // => Session = 0^secret % P => 0
    {
        A := dh.NewDh3(P)
        B := dh.NewDh3(P)

        s2 := sha1.Sum([]byte{})
        key := s2[:16]

        ciphertext := send(A, B, plaintext)

        iv := ciphertext[len(ciphertext)-16:]
        plaintext2, err := aes.Cbcdecrypt(ciphertext[:len(ciphertext)-16], key, iv)
        if err != nil {
            log.Fatal(err)
        }

        fmt.Printf("intercepted: %v, %q\n", plaintext2, string(plaintext2))

        ciphertext2 := echo(A, B, ciphertext)
        match := verify(A, B, plaintext, ciphertext2)
        if !match {
            log.Fatal(fmt.Sprintf("verify() failed"))
        }
    }

    // Man-in-the-Middle with g = p-1
    //
    // => Public = (P-1)^secret % P => 1 if secret is even (including zero)
    // => Session = 1^secret % P => 1
    //
    // => Public = (P-1)^secret % P => P-1 if secret is odd
    // => Session = (P-1)^secret % P => 1 if secret is even, P-1 if odd
    {
        P1 := new(big.Int)
        P1.Sub(P, big.NewInt(1))

        var Aeven *dh.Dh

        for {
            Aeven = dh.NewDh3(P1)
            if Aeven.Public.Cmp(big.NewInt(1)) == 0 {
                break
            }
        }

        B := dh.NewDh3(P1)

        s2 := sha1.Sum([]byte{1})
        key := s2[:16]

        ciphertext := send(Aeven, B, plaintext)

        iv := ciphertext[len(ciphertext)-16:]
        plaintext2, err := aes.Cbcdecrypt(ciphertext[:len(ciphertext)-16], key, iv)
        if err != nil {
            log.Fatal(err)
        }

        fmt.Printf("intercepted (even): %v, %q\n", plaintext2, string(plaintext2))

        ciphertext2:= echo(Aeven, B, ciphertext)
        match := verify(Aeven, B, plaintext, ciphertext2)
        if !match {
            log.Fatal(fmt.Sprintf("verify() failed"))
        }
    }

    {
        P1 := new(big.Int)
        P1.Sub(P, big.NewInt(1))

        var Aodd *dh.Dh

        for {
            Aodd = dh.NewDh3(P1)
            if Aodd.Public.Cmp(P1) == 0 {
                break
            }
        }

        B := dh.NewDh3(P1)

        var key []byte

        if B.Public.Cmp(P1) == 0 {
            s2 := sha1.Sum(P1.Bytes())
            key = s2[:16]
        } else {
            s2 := sha1.Sum([]byte{1})
            key = s2[:16]
        }

        ciphertext := send(Aodd, B, plaintext)

        iv := ciphertext[len(ciphertext)-16:]
        plaintext2, err := aes.Cbcdecrypt(ciphertext[:len(ciphertext)-16], key, iv)
        if err != nil {
            log.Fatal(err)
        }

        fmt.Printf("intercepted  (odd): %v, %q\n", plaintext2, string(plaintext2))

        ciphertext2:= echo(Aodd, B, ciphertext)
        match := verify(Aodd, B, plaintext, ciphertext2)
        if !match {
            log.Fatal(fmt.Sprintf("verify() failed"))
        }
    }
}

func send(A, B *dh.Dh, plaintext []byte) []byte {
    s := A.Session(B)
    s2 := sha1.Sum(s.Bytes())
    key := s2[:16]

    iv := rand.Bytes(16)

    if len(plaintext) % 16 != 0 {
        log.Fatal(errors.New(fmt.Sprintf("send: len(plaintext) % 16 != 0")))
    }

    ciphertext, err := aes.Cbcencrypt(plaintext, key, iv)
    if err != nil {
        log.Fatal(err)
    }

    return append(ciphertext, iv...)
}

func echo(A, B *dh.Dh, ciphertext []byte) []byte {
    s := A.Session(B)
    s2 := sha1.Sum(s.Bytes())
    key := s2[:16]

    iv := ciphertext[len(ciphertext)-16:]

    if (len(ciphertext)-16) % 16 != 0 {
        log.Fatal(errors.New(fmt.Sprintf("echo: len(ciphertext) % 16 != 0")))
    }

    plaintext, err := aes.Cbcdecrypt(ciphertext[:len(ciphertext)-16], key, iv)
    if err != nil {
        log.Fatal(err)
    }

    iv2 := rand.Bytes(16)

    ciphertext2, err := aes.Cbcencrypt(plaintext, key, iv2)
    if err != nil {
        log.Fatal(err)
    }

    return append(ciphertext2, iv2...)
}

func verify(A, B *dh.Dh, plaintext, ciphertext []byte) bool {
    s := A.Session(B)
    s2 := sha1.Sum(s.Bytes())
    key := s2[:16]

    iv := ciphertext[len(ciphertext)-16:]

    if (len(ciphertext)-16) % 16 != 0 {
        log.Fatal(errors.New(fmt.Sprintf("echo: len(ciphertext) % 16 != 0")))
    }

    plaintext2, err := aes.Cbcdecrypt(ciphertext[:len(ciphertext)-16], key, iv)
    if err != nil {
        log.Fatal(err)
    }

    return bytes.Compare(plaintext, plaintext2) == 0
}
