package main

import (
    "./aes"
    "./pkcs7"
    "errors"
    "log"
    "math/rand"
    "strings"
    "time"
)

var key, iv []byte

func main() {
    rand.Seed(time.Now().Unix())
    key = randbytes(16)
    iv = randbytes(16)

    // The prefix ends on a block boundary (32 bytes)

                              // x  ;  a  d  m  i  n  =  t  r  u  e
    cipher, err := oracle([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
    if err != nil {
        log.Fatal(err)
    }

    // Modify the last block of the prefix so that when it is xor'ed with the zero input
    // (during cbc decryption) the desired next block (first block of input) is achieved.

    block := cipher[16:32]
    desired := []byte("x;admin=true")

    for i:=0; i<len(desired); i++ {
        block[i] = block[i] ^ desired[i]
    }

    cipher2 := make([]byte, len(cipher))
    copy(cipher2, cipher)
    copy(cipher2[16:32], block)

    admin, err := unoracle(cipher2)
    if err != nil {
        log.Fatal(err)
    }

    if !admin {
        log.Fatal(errors.New("admin not true"))
    }
}

func oracle(input []byte) ([]byte, error) {
    prefix := []byte("comment1=cooking%20MCs;userdata=")
    postfix := []byte(";comment2=%20like%20a%20pound%20of%20bacon")

    encoded := []byte(strings.Replace(strings.Replace(string(input),
                                                      ";", "%3b", -1),
                                      "=", "%3d", -1))

    input2 := append(append(prefix, encoded...), postfix...)

    padded, err := pkcs7.Pad(input2, uint(len(key)))
    if err != nil {
        return nil, err
    }

    cipher, err := aes.Cbcencrypt(padded, key, iv)
    if err != nil {
        return nil, err
    }

    return cipher, nil
}

func unoracle(input []byte) (bool, error) {
    padded, err := aes.Cbcdecrypt(input, key, iv)
    if err != nil {
        return false, err
    }

    plain, err := pkcs7.Unpad(padded, uint(len(key)))
    if err != nil {
        return false, err
    }

    return strings.Contains(string(plain), ";admin=true;"), nil
}

func randbytes(n uint) []byte {
    rv := make([]byte, n)

    for i:=uint(0); i<n; i++ {
        rv[i] = byte(rand.Intn(256))
    }

    return rv
}
