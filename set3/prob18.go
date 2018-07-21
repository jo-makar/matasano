package main

import (
    "./aes"
    "../set1/base64"
    "bytes"
    "fmt"
    "log"
)

func main() {
    decoded, err := base64.Decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
    if err != nil {
        log.Fatal(err)
    }

    key := []byte("YELLOW SUBMARINE")
    nonce := uint64(0)

    plain, err := aes.Ctrdecrypt(decoded, key, nonce)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(plain)
    fmt.Println(string(plain))

    cipher, err := aes.Ctrencrypt(plain, key, nonce)
    if err != nil {
        log.Fatal(err)
    }

    if !bytes.Equal(cipher, decoded) {
        log.Fatal("encryption incorrect")
    }
}
