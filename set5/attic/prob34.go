package main

import (
    "./dh"
    "../set2/aes"
    "../set4/rand"
    "../set4/sha1"
    "bytes"
    "errors"
    "fmt"
    "log"
)

func main() {
    A := dh.NewDh()
    B := dh.NewDh()

    plaintext := []byte("Hi! How are you?")

    // Echo behavior verification

    ciphertext, err := send(A, B, plaintext)
    if err != nil {
        log.Fatal(err)
    }

    ciphertext2, err := echo(A, B, ciphertext)
    if err != nil {
        log.Fatal(err)
    }

    match, err := verify(A, B, plaintext, ciphertext2)
    if err != nil {
        log.Fatal(err)
    }

    if !match {
        log.Fatal(fmt.Sprintf("verify() failed"))
    }

    // Man-in-the-Middle attack

    fakeA := dh.NewDh2(A.P)
    fakeB := dh.NewDh2(B.P)

    // P^secret % P => 0 for all secret (except secret=0)

    //s2 := sha1.Sum([]byte{0})
    s2 := sha1.Sum([]byte{})
    key := s2[:16]

    ciphertext, err = send(fakeA, fakeB, plaintext)
    if err != nil {
        log.Fatal(err)
    }

    iv := ciphertext[len(ciphertext)-16:]
    plaintext2, err := aes.Cbcdecrypt(ciphertext[:len(ciphertext)-16], key, iv)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("intercepted send():", plaintext2)
    fmt.Println("                   ", string(plaintext2))
    if bytes.Compare(plaintext, plaintext2) != 0 {
        log.Fatal(fmt.Sprintf("interception mismatch"))
    }

    ciphertext2, err = echo(fakeA, fakeB, ciphertext)
    if err != nil {
        log.Fatal(err)
    }

    iv = ciphertext[len(ciphertext)-16:]
    plaintext2, err = aes.Cbcdecrypt(ciphertext[:len(ciphertext)-16], key, iv)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("intercepted echo():", plaintext2)
    fmt.Println("                   ", string(plaintext2))
    if bytes.Compare(plaintext, plaintext2) != 0 {
        log.Fatal(fmt.Sprintf("interception mismatch"))
    }

    match, err = verify(fakeA, fakeB, plaintext, ciphertext2)
    if err != nil {
        log.Fatal(err)
    }

    if !match {
        log.Fatal(fmt.Sprintf("verify() failed"))
    }
}

func send(A, B *dh.Dh, plaintext []byte) ([]byte, error) {
    s := A.Session(B)
    s2 := sha1.Sum(s.Bytes())
    key := s2[:16]

    iv := rand.Bytes(16)

    if len(plaintext) % 16 != 0 {
        return nil, errors.New(fmt.Sprintf("send: len(plaintext) % 16 != 0"))
    }

    ciphertext, err := aes.Cbcencrypt(plaintext, key, iv)
    if err != nil {
        return nil, err
    }

    return append(ciphertext, iv...), nil
}

func echo(A, B *dh.Dh, ciphertext []byte) ([]byte, error) {
    s := A.Session(B)
    s2 := sha1.Sum(s.Bytes())
    key := s2[:16]

    iv := ciphertext[len(ciphertext)-16:]

    if (len(ciphertext)-16) % 16 != 0 {
        return nil, errors.New(fmt.Sprintf("echo: len(ciphertext) % 16 != 0"))
    }

    plaintext, err := aes.Cbcdecrypt(ciphertext[:len(ciphertext)-16], key, iv)
    if err != nil {
        return nil, err
    }

    iv2 := rand.Bytes(16)

    ciphertext2, err := aes.Cbcencrypt(plaintext, key, iv2)
    if err != nil {
        return nil, err
    }

    return append(ciphertext2, iv2...), nil
}

func verify(A, B *dh.Dh, plaintext, ciphertext []byte) (bool, error) {
    s := A.Session(B)
    s2 := sha1.Sum(s.Bytes())
    key := s2[:16]

    iv := ciphertext[len(ciphertext)-16:]

    if (len(ciphertext)-16) % 16 != 0 {
        return false, errors.New(fmt.Sprintf("echo: len(ciphertext) % 16 != 0"))
    }

    plaintext2, err := aes.Cbcdecrypt(ciphertext[:len(ciphertext)-16], key, iv)
    if err != nil {
        return false, err
    }

    return bytes.Compare(plaintext, plaintext2) == 0, nil
}
