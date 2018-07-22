package main

import (
    "./base64"
    "./rand"
    aes2 "../set2/aes"
    aes3 "../set3/aes"
    "fmt"
    "log"
    "path/filepath"
    "runtime"
)

func main() {
    _, path, _, _ := runtime.Caller(0)
    origciphertext, err := base64.Decodepath(filepath.Join(filepath.Dir(path), "prob25.txt"))
    if err != nil {
        log.Fatal(err)
    }

    plaintext, err := aes2.Ecbdecrypt(origciphertext, []byte("YELLOW SUBMARINE"))
    if err != nil {
        log.Fatal(err)
    }

    // Re-encrypting in CTR mode and a random key
    key := rand.Bytes(16)
    nonce := rand.Uint64()
    ciphertext, err := aes3.Ctrencrypt(plaintext, key, nonce)
    if err != nil {
        log.Fatal(err)
    }

    // Edit the plaintext to be all zeros, then the new ciphertext is the cipher output.
    // This output xor'ed with the original ciphertext gives the plaintext.

    plaintextedit := make([]byte, len(ciphertext))
    keystream, err := edit(ciphertext, key, nonce, 0, plaintextedit)
    if err != nil {
        log.Fatal(err)
    }

    recovered := make([]byte, len(ciphertext))
    for i:=0; i<len(ciphertext); i++ {
        recovered[i] = ciphertext[i] ^ keystream[i]
    }

    fmt.Println(recovered)
    fmt.Println(string(recovered))
}

func edit(ciphertext, key []byte, nonce uint64, offset int, newplaintext []byte) ([]byte, error) {
    plaintext, err := aes3.Ctrdecrypt(ciphertext, key, nonce)
    if err != nil {
        return nil, err
    }

    plaintext2 := make([]byte, len(plaintext))
    copy(plaintext2, plaintext)

    for i, j := offset, 0; j < len(newplaintext); i, j = i+1, j+1 {
        if i < len(plaintext2) {
            plaintext2[i] = newplaintext[j]
        } else {
            plaintext2 = append(plaintext2, newplaintext[j])
        }
    }

    ciphertext2, err := aes3.Ctrencrypt(plaintext2, key, nonce)
    if err != nil {
        return nil, err
    }

    return ciphertext2, nil
}
