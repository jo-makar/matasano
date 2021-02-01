package main

import (
    "./rand"
    "../set2/pkcs7"
    "../set3/aes"
    "bytes"
    "errors"
    "log"
)

var key []byte = rand.Bytes(16)
var nonce uint64 = rand.Uint64()

func main() {
    // Set the target region to be all zeros, then that portion will be the keystream.
    // Use this to force the desired plaintext region for decryption.

                                  // x  ;  a  d  m  i  n  =  t  r  u  e
    ciphertext, err := oracle([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
    if err != nil {
        log.Fatal(err)
    }

    buf := new(bytes.Buffer)

    // Copy the prefix
    buf.Write(ciphertext[0:32])

    desired := []byte("x;admin=true")
    for i:=0; i<len(desired); i++ {
        buf.WriteByte(desired[i] ^ ciphertext[32+i])
    }

    // Copy the postfix
    buf.Write(ciphertext[32+len(desired):])

    admin, err := unoracle(buf.Bytes())
    if err != nil {
        log.Fatal(err)
    }

    if !admin {
        log.Fatal(errors.New("admin not true"))
    }
}

func oracle(input []byte) ([]byte, error) {
    buf := new(bytes.Buffer)

    buf.WriteString("comment1=cooking%20MCs;userdata=")

    buf.Write(bytes.Replace(
                  bytes.Replace(input, []byte{';'}, []byte{'%','3','b'}, -1),
                                       []byte{'='}, []byte{'%','3','d'}, -1))

    buf.WriteString(";comment2=%20like%20a%20pound%20of%20bacon")

    padded, err := pkcs7.Pad(buf.Bytes(), uint(len(key)))
    if err != nil {
        return nil, err
    }

    ciphertext, err := aes.Ctrencrypt(padded, key, nonce)
    if err != nil {
        return nil, err
    }

    return ciphertext, nil
}

func unoracle(input []byte) (bool, error) {
    padded, err := aes.Ctrdecrypt(input, key, nonce)
    if err != nil {
        return false, err
    }

    plaintext, err := pkcs7.Unpad(padded, uint(len(key)))
    if err != nil {
        return false, err
    }

    return bytes.Contains(plaintext, []byte(";admin=true;")), nil
}
