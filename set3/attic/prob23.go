package main

import (
    "./mt19937"
    "errors"
    "fmt"
    "log"
    "math/rand"
    "time"
)

func main() {
    n := []uint32{0x00000000, 0xffffffff, 0xaaaaaaaa, 0x55555555, 0xcccccccc, 0x33333333,
                  0xc3c3c3c3, 0x3c3c3c3c, 0xa5a5a5a5, 0x5a5a5a5a, 0xcafebabe, 0xbeeffeed}

    for i, v := range n {
        w := mt19937.Untemper(temper(v))
        if w != v {
            log.Fatal(errors.New(fmt.Sprintf("mismatch: i=%d, w=%d, v=%d", i, w, v)))
        }
    }

    rand.Seed(time.Now().Unix())

    rng1 := mt19937.NewMt19937(rand.Uint32())
    var state1 []uint32

    for i:=0; i<624; i++ {
        state1 = append(state1, mt19937.Untemper(rng1.Rand()))
    }

    rng2 := mt19937.NewMt19937state(state1)

    for i:=0; i<1000; i++ {
        w, v := rng1.Rand(), rng2.Rand()
        if w != v {
            log.Fatal(errors.New(fmt.Sprintf("mismatch: i=%d, w=%d, v=%d", i, w, v)))
        }
    }

    // To mitigate the attack, state to output calculation should be non-invertible.
    // For example, as suggested by use of a cryptographic hashing function.
}

func temper(v uint32) uint32 {
    var y uint32 = v
    y ^= y >> 11
    y ^= (y << 7) & 2636928640
    y ^= (y << 15) & 4022730752
    y ^= y >> 18
    return y
}
