package main

import (
    "./rsa"
    "bytes"
    "log"
)

func main() {
    privkey, pubkey := rsa.Keypair(256)

    plaintext := []byte("hello world")
    ciphertext := pubkey.Encrypt(plaintext)
    plaintext2 := privkey.Decrypt(ciphertext)

    if !bytes.Equal(plaintext, plaintext2) {
        log.Fatal("Decrypt failed")
    }
}
