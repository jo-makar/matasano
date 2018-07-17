package main

import (
    "./aes"
    "./pkcs7"
    "../set1/base64"
    "bytes"
    "errors"
    "fmt"
    "log"
    "math/rand"
    "time"
)

var key, unknown []byte

func main() {
    rand.Seed(time.Now().Unix())
    key = randbytes(16)

    var err error
    unknown, err = base64.Decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
                                 "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
                                 "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
                                 "YnkK")
    if err != nil {
        log.Fatal(err)
    }

    // Use a specific plaintext to delineate the prefix.
    // Specifically run the oracle repeatedly against a specific plaintext and look for the
    // corresponding ciphertexts when the prefix ends on a block boundary.

    plain := make([]byte, 5*len(key))

    for i:=0; i<len(key); i++ {
        plain[i] = byte(i)
    }

    for i:=len(key); i<2*len(key); i++ {
        plain[i] = 'A'
    }

    copy(plain[2*len(key):3*len(key)], plain[0:len(key)])

    for i:=3*len(key); i<4*len(key); i++ {
        plain[i] = 'B'
    }

    copy(plain[4*len(key):5*len(key)], plain[0:len(key)])

    fmt.Println("plaintext =", plain)

    cipher := make([]byte, len(plain))
    found := false
    var i int

    for i=0; !found && i<1000; i++ {
        testcipher, err := oracle(plain)
        if err != nil {
            log.Fatal(err)
        }

        testblocks := split(testcipher, uint(len(key)))

        for j:=0; j < len(testblocks) - len(plain)/len(key) + 1; j++ {
            if bytes.Equal(testblocks[j], testblocks[j+2]) &&
               bytes.Equal(testblocks[j], testblocks[j+4]) &&
               !bytes.Equal(testblocks[j], testblocks[j+1]) &&
               !bytes.Equal(testblocks[j], testblocks[j+3]) &&
               !bytes.Equal(testblocks[j+1], testblocks[j+3]) {

                copy(cipher, testcipher[j*len(key) : j*len(key)+len(plain)])
                found = true
                break
            }
        }
    }

    if !found {
        log.Fatal(errors.New("ciphertext not found"))
    }
    fmt.Printf("ciphertext found after %d iterations\n", i+1)

    // Verify the found ciphertext by searching for it repeatedly

    count := 0
    for i=0; i<1000; i++ {
        c, err := oracle(plain)
        if err != nil {
            log.Fatal(err)
        }

        if bytes.Contains(c, cipher) {
            count++
        }
    }

    if count == 0 {
        log.Fatal(errors.New("ciphertext not verified"))
    }
    fmt.Printf("ciphertext verified, found %d times in %d iterations\n", count, i)

    // FIXME STOPPED
}

func oracle(input []byte) ([]byte, error) {
    prefix := randbytes(uint(rand.Intn(100)))
    input2 := append(append(prefix, input...), unknown...)

    padded, err := pkcs7.Pad(input2, uint(len(key)))
    if err != nil {
        return nil, err
    }

    cipher, err := aes.Ecbencrypt(padded, key)
    if err != nil {
        return nil, err
    }

    return cipher, nil
}

func randbytes(n uint) []byte {
    rv := make([]byte, n)

    for i:=uint(0); i<n; i++ {
        rv[i] = byte(rand.Intn(256))
    }

    return rv
}

// Split a byte array into n-sized chunks.
// Do not include the final chunk if it less than n bytes.
func split(data []byte, n uint) [][]byte {
    if n == 0 {
        log.Fatal(errors.New("split: n == 0"))
    }
    if n > uint(len(data)) {
        log.Fatal(errors.New("split: n > len(data)"))
    }

    rv := make([][]byte, uint(len(data))/n)

    for i, j := uint(0), 0; i+n <= uint(len(data)); i, j = i+n, j+1 {
        rv[j] = data[i:i+n]
    }

    return rv
}
