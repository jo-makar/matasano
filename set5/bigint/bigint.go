package bigint

import (
    "log"
    "math"
    "math/big"
    "math/rand"
    "time"
)

func Modexp(b, e, m *big.Int) *big.Int {
    // For simplicity error here rather than passing them up
    //.(ie akin to how division by zero is handled)

    zero := big.NewInt(0)
    one := big.NewInt(1)
    two := big.NewInt(2)

    if m.Cmp(one) == -1 {
        log.Fatal("modexp: m < 1")
    } else if m.Cmp(one) == 0 {
        return big.NewInt(0)
    }

    if e.Cmp(zero) == -1 {
        // Consider adding support for this later
        log.Fatal("modexp: e < 0")
    } else if e.Cmp(zero) == 0 {
        return big.NewInt(1)
    } else if e.Cmp(one) == 0 {
        return new(big.Int).Mod(b, m)
    }

    c := big.NewInt(1)
    b2 := new(big.Int).Mod(b, m)
    e2 := new(big.Int).Set(e)

    // While e2 > 0
    for e2.Cmp(zero) == 1 {

        // If e2 % 2 == 1
        if new(big.Int).Mod(e2, two).Cmp(one) == 0 {
            // c = (c * b2) % m
            c.Mul(c, b2).Mod(c, m)
        }

        // e2 = e2 >> 1
        e2.Rsh(e2, 1)

        // b2 = (b2 * b2) % m
        b2.Mul(b2, b2).Mod(b2, m)
    }

    return c
}

func Fromhex(s string) *big.Int {
    i := new(big.Int)
    if _, ok := i.SetString(s, 16); !ok {
        log.Fatal("bigint.IntFromHex: SetString failed")
    }
    return i
}

func Frombytes(b []byte) *big.Int {
    i := new(big.Int)
    return i.SetBytes(b)
}

var seeded bool = false

// math/big.Int analog of math/rand.Intn
func Randintn(n *big.Int) *big.Int {
    if !seeded {
        rand.Seed(time.Now().Unix())
        seeded = true
    }

    if n.BitLen() == 0 {
        log.Fatal("bigint.RandIntn: n == 0")
    }

    if n.BitLen() < 8 {
        bits := int(math.Pow(2, float64(n.BitLen())))
        return new(big.Int).SetInt64(int64(rand.Intn(bits)))
    } else {
        b := make([]byte, n.BitLen()/8)
        for i, _ := range b {
            b[i] = byte(rand.Intn(256))
        }
        return new(big.Int).SetBytes(b)
    }
}
