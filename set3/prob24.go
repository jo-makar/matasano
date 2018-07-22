package main

import (
    "./mt19937"
    "bytes"
    "errors"
    "fmt"
    "log"
    "math/rand"
    "time"
)

func main() {
    rand.Seed(time.Now().Unix())

    // MT19937 stream cipher

    plain := append(randbytes(uint(5 + rand.Intn(11))), []byte("AAAAAAAAAAAAAA")...)
    cipher := encrypt(uint16(rand.Intn(65536)), plain)

    found := false
    for i:=0; i<65536; i++ {
        if i>0 && i%10000 == 0 {
            fmt.Printf("Testing seed = %d\n", i)
        }

        p := make([]byte, len(cipher))
        for j:=len(p)-14; j<len(p); j++ {
            p[j] = 'A'
        }

        c := encrypt(uint16(i), p)
        if bytes.Equal(cipher[len(cipher)-14:], c[len(c)-14:]) {
            fmt.Printf("Found key seed = %d\n", i)
            found = true
            break
        }
    }

    if !found {
        log.Fatal(errors.New("unable to find key seed"))
    }

    // Password reset token

    token := resettoken(uint16(time.Now().Unix()))

    s := uint16(time.Now().Unix())

    found = false
    for i:=s; i>s-60; i-- {
        t := resettoken(i)
        if bytes.Equal(token, t) {
            fmt.Printf("Found token seed = %d\n", i)
            found = true
            break
        }
    }

    if !found {
        log.Fatal(errors.New("unable to find token seed"))
    }
}

func encrypt(seed uint16, plaintext []byte) []byte {
    m := mt19937.NewMt19937(uint32(seed))

    var n uint32 = m.Rand() // Current random number
    var b uint8  = 0        // Byte index: 0-4, 4 meaning next

    ciphertext := make([]byte, len(plaintext))

    for i:=0; i<len(plaintext); i, b = i+1, b+1 {
        if b == 4 {
            n = m.Rand()
            b = 0
        }

        ciphertext[i] = plaintext[i] ^ uint8(n >> (8*b))
    }

    return ciphertext
}

func resettoken(seed uint16) []byte {
    m := mt19937.NewMt19937(uint32(seed))

    var n uint32 = m.Rand()
    var b uint8  = 0

    token := make([]byte, 10)
    for i:=0; i<len(token); i, b = i+1, b+1 {
        if b == 4 {
            n = m.Rand()
            b = 0
        }

        token[i] = uint8(n >> (8*b))
    }

    return token
}

func randbytes(n uint) []byte {
    rv := make([]byte, n)

    for i:=uint(0); i<n; i++ {
        rv[i] = byte(rand.Intn(256))
    }

    return rv
}
