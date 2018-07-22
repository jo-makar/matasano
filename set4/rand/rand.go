package rand

import (
    "math/rand"
    "time"
)

var seeded bool = false

func Bytes(n int) []byte {
    if !seeded {
        rand.Seed(time.Now().Unix())
        seeded = true
    }

    if n <= 0 {
        n = 0
    }

    b := make([]byte, n)
    for i:=0; i<n; i++ {
        b[i] = byte(rand.Intn(256))
    }

    return b
}

func Uint64() uint64 {
    if !seeded {
        rand.Seed(time.Now().Unix())
        seeded = true
    }

    return (uint64(rand.Uint32()) << 32) | uint64(rand.Uint32())
}
