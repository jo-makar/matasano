package bigint

import (
    crand "crypto/rand"
    "crypto/rsa"
    "log"
    "math"
    "math/big"
    mrand "math/rand"
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
        mrand.Seed(time.Now().Unix())
        seeded = true
    }

    if n.BitLen() == 0 {
        log.Fatal("bigint.RandIntn: n == 0")
    }

    if n.BitLen() < 8 {
        bits := int(math.Pow(2, float64(n.BitLen())))
        return new(big.Int).SetInt64(int64(mrand.Intn(bits)))
    } else {
        b := make([]byte, n.BitLen()/8)
        for i, _ := range b {
            b[i] = byte(mrand.Intn(256))
        }
        return new(big.Int).SetBytes(b)
    }
}

func Primes(bits int) (*big.Int, *big.Int) {
    key, err := rsa.GenerateKey(crand.Reader, bits)
    if err != nil {
        log.Fatal(err)
    }

    return key.Primes[0], key.Primes[1]
}

func Coprime(a, b *big.Int) bool {
    gcd := new(big.Int).GCD(nil, nil, a, b)
    return gcd.Cmp(big.NewInt(1)) == 0
}

// Inverse multiplicative modulo
// Ie given a and m find b such that (a * b) mod m = 1
func Invmod(a, m *big.Int) *big.Int {
    // The inverse will not exist unless a and m are coprime
    if !Coprime(a, m) {
        log.Fatal("Invmod: !Coprime(a, m)")
    }

    var rv *big.Int

    // Extended Euclidean algorithm which solves ax + by = gcd(a, b)
    {
        xi := big.NewInt(1)
        yi := big.NewInt(0)
        qi := big.NewInt(0)
        ri := new(big.Int).Add(new(big.Int).Mul(a, xi),
                               new(big.Int).Mul(m, yi))

        xj := big.NewInt(0)
        yj := big.NewInt(1)
        qj := big.NewInt(0)
        rj := new(big.Int).Add(new(big.Int).Mul(a, xj),
                               new(big.Int).Mul(m, yj))

        for {
            qk := new(big.Int).Div(ri, rj)
            rk := new(big.Int).Mod(ri, rj)
            xk := new(big.Int).Sub(xi, new(big.Int).Mul(qk, xj))
            yk := new(big.Int).Sub(yi, new(big.Int).Mul(qk, yj))

            if rk.Cmp(big.NewInt(0)) == 0 {
                break
            }

            qi, qj = qj, qk
            ri, rj = rj, rk
            xi, xj = xj, xk
            yi, yj = yj, yk
        }

        // If rj is one then a and m are coprime
        if rj.Cmp(big.NewInt(1)) != 0 {
            log.Fatal("Invmod: rj != 0")
        }

        // rj = 1 = a*xj + m*yj => (a * xj) mod m = 1
        rv = xj

        // Just to ensure qi is "used" for compiler/interpreter
        qi.Add(qi, big.NewInt(0))
    }


    if rv.Cmp(big.NewInt(0)) < 0 {
        rv.Add(rv, m)
    }
    if rv.Cmp(big.NewInt(0)) < 0 {
        log.Fatal("Invmod: rv < 0")
    }
    return rv
}
