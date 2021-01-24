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

    // Determine the cipher block length, specifically:
    // Look for the first change in ciphertext length as the plaintext length increases

    cipher, err := oracle([]byte{'A'})
    if err != nil {
        log.Fatal(err)
    }

    var blocklen uint
    minlen := uint(len(cipher))

    for i:=2; i<100; i++ {
        input := make([]byte, i)
        for j:=0; j<i; j++ {
            input[j] = 'A'
        }

        cipher, err = oracle(input)
        if err != nil {
            log.Fatal(err)
        }

        if uint(len(cipher)) > minlen {
            blocklen = uint(len(cipher)) - minlen
            break
        }
    }

    if blocklen == 0 {
        log.Fatal(errors.New("block length undetermined"))
    }

    fmt.Println("block length =", blocklen)

    // Verify the cipher uses ECB

    input := make([]byte, blocklen * 2)
    for i:=0; i<len(input); i++ {
        input[i] = 'A'
    }

    cipher, err = oracle(input)
    if err != nil {
        log.Fatal(err)
    }

    if !bytes.Equal(cipher[0:blocklen], cipher[blocklen:blocklen*2]) {
        log.Fatal(errors.New(fmt.Sprintf("oracle not using ecb")))
    }

    fmt.Println("ecb mode verified")

    // Determine the length of the unknown string, specifically:
    // Look for the first change in ciphertext length as the plaintext length increases
    // then the unknown string length can be calculated from the byte count at transition

    cipher, err = oracle([]byte{})
    if err != nil {
        log.Fatal(err)
    }

    var unknownlen uint
    minlen = uint(len(cipher))

    for i:=uint(1); i<100; i++ {
        input = make([]byte, i)

        cipher, err = oracle(input)
        if err != nil {
            log.Fatal(err)
        }

        if uint(len(cipher)) > minlen {
            // minlen / blocklen will always be >= 1
            unknownlen = uint(minlen/blocklen-1)*blocklen + blocklen-i
            break
        }
    }

    if unknownlen == 0 {
        log.Fatal(errors.New("unknown string length undetermined"))
    }

    fmt.Println("unknown length =", unknownlen)
    if unknownlen != uint(len(unknown)) {
        log.Fatal(errors.New("unknown length incorrect"))
    }

    // Byte-by-byte dictionary attack:
    // The idea is to slide a given block to the right so that all but the last byte is known,
    // then iterate through the possibilities for that last byte until a match is found.
    // Note that only the first block has bytes prepended, after the first block the prepends are
    // purely to slide bytes to the right in the later blocks.

    discovered := make([]byte, unknownlen)

    for i:=uint(0); i<uint(len(discovered)); i++ {
        input := make([]byte, blocklen-(i%blocklen+1))
        for j:=uint(0); j < blocklen-(i%blocklen+1); j++ {
            input[j] = 'A'
        }

        target, err := oracle(input)
        if err != nil {
            log.Fatal(err)
        }

        found := false
        for j:=0; j<256; j++ {
            testinput := bytes.NewBuffer(input)
            for k:=uint(0); uint(testinput.Len()) < (i/blocklen+1)*blocklen - 1; k++ {
                testinput.WriteByte(discovered[k])
            }
            testinput.WriteByte(byte(j))

            testoutput, err := oracle(testinput.Bytes())
            if err != nil {
                log.Fatal(err)
            }

            if bytes.Equal(testoutput[(i/blocklen)*blocklen : (i/blocklen+1)*blocklen],
                               target[(i/blocklen)*blocklen : (i/blocklen+1)*blocklen]) {
                discovered[i] = byte(j)
                found = true
                break
            }
        }

        if !found {
            log.Fatal(errors.New("matching block not found"))
        }
    }

    fmt.Println("unknown =", discovered)
    fmt.Println(string(discovered))

    if !bytes.Equal(discovered, unknown) {
        log.Fatal(errors.New("unknown incorrect"))
    }
}

func oracle(input []byte) ([]byte, error) {
    input2 := append(input, unknown...)

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
