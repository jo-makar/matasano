package main

import (
    "./aes"
    "./pkcs7"
    "bytes"
    "fmt"
    "log"
    "math/rand"
    "time"
)

func main() {
    rand.Seed(time.Now().Unix())

    input := make([]byte, 100)
    for i:=0; i<len(input); i++ {
        input[i] = 'x'
    }

    for trial:=0; trial<10; trial++ {
        cipher, err := oracle(input)
        if err != nil {
            log.Fatal(err)
        }

        // If the second through nth-2 plaintext blocks are equal then
        // the second through nth-2 ciphertext blocks are equal with ECB

        allequal := true

        for i:=16*2; i<len(cipher)-16*2; i+=16 {
            if !bytes.Equal(cipher[16:16*2], cipher[i:i+16]) {
                allequal = false
                break
            }
        }

        mode := "ecb"
        if !allequal {
            mode = "cbc"
        }

        fmt.Printf("trial %d: %s used\n", trial, mode)
    }
}

func oracle(input []byte) ([]byte, error) {
    key := randbytes(16)

    input2 := append(append(randbytes(uint(5 + rand.Intn(6))),
                            input...),
                     randbytes(uint(5 + rand.Intn(6)))...)

    padded, err := pkcs7.Pad(input2, uint(len(key)))
    if err != nil {
        return nil, err
    }

    var cipher []byte

    if rand.Intn(2) == 0 {
        cipher, err = aes.Cbcencrypt(padded, key, randbytes(uint(len(key))))
        if err != nil {
            return nil, err
        }
    } else {
        cipher, err = aes.Ecbencrypt(padded, key)
        if err != nil {
            return nil, err
        }
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
