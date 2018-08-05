package srp

import (
    "../bigint"
    "../../set4/rand"
    "bytes"
    "crypto/sha256"
    "encoding/binary"
    "log"
    "math/big"
    "strings"
)

var N = bigint.Fromhex("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
                       "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
                       "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
                       "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
                       "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
                       "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
                       "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
                       "fffffffffffff")
var g = big.NewInt(2)
var k = big.NewInt(3)

type Client struct {
    I, P string
    a, A *big.Int

    salt []byte
    B *big.Int
}

func (c *Client) Init(I, P string) {
    c.I, c.P = I, P

    c.a = bigint.Randintn(N)
    c.A = bigint.Modexp(g, c.a, N)
}

func NewClient(I, P string) *Client {
    c := new(Client)
    c.Init(I, P)
    return c
}

func (c *Client) Send(s *Server) {
    if strings.Compare(c.I, s.I) != 0 {
        log.Fatal("srp: I mismatch")
    }

    s.A = c.A
}

func (c *Client) hmac() []byte {
    buf := append(c.A.Bytes(), c.B.Bytes()...)
    uH := sha256.Sum256(buf)
    u := bigint.Frombytes(uH[:])

    buf = make([]byte, 0)
    buf = append(append(buf, c.salt...), []byte(c.P)...)
    xH := sha256.Sum256(buf)
    x := bigint.Frombytes(xH[:])

    // Using the given formula for S is too slow to calculate.
    // This version is simplified using modular arithmetic:
    // S = modexp(((B % N) - (((k % N) * modexp(g, x, N)) % N)) % N, a + u * x, N)

    // base = ((B % N) - (((k % N) * modexp(g, x, N)) % N)) % N
    t1 := new(big.Int).Mod(c.B, N)
    t2 := new(big.Int).Mod(k, N)
    t3 := bigint.Modexp(g, x, N)
    t4 := new(big.Int).Mul(t2, t3)
    t5 := new(big.Int).Mod(t4, N)
    t6 := new(big.Int).Sub(t1, t5)
    base := new(big.Int).Mod(t6, N)

    t1 = new(big.Int).Mul(u, x)
    exp := new(big.Int).Add(c.a, t1)

    S := bigint.Modexp(base, exp, N)
    K := sha256.Sum256(S.Bytes())

    return hmacsha256(K[:], c.salt)
}

type Server struct {
    I, P string
    b, B *big.Int
    salt []byte
    v *big.Int

    A *big.Int
}

func (s *Server) Init(I, P string) {
    s.I, s.P = I, P

    s.salt = make([]byte, 8)
    binary.BigEndian.PutUint64(s.salt, rand.Uint64())

    buf := make([]byte, 0)
    buf = append(append(buf, s.salt...), []byte(s.P)...)

    xH := sha256.Sum256(buf)
    x := bigint.Frombytes(xH[:])
    s.v = bigint.Modexp(g, x, N)

    s.b = bigint.Randintn(N)
    s.B = new(big.Int).Add(bigint.Modexp(g, s.b, N),
                           new(big.Int).Mul(k, s.v))
}

func NewServer(I, P string) *Server {
    s := new(Server)
    s.Init(I, P)
    return s
}

func (s *Server) Send(c *Client) {
    c.salt = s.salt
    c.B = s.B
}

func (s *Server) hmac() []byte {
    buf := append(s.A.Bytes(), s.B.Bytes()...)
    uH := sha256.Sum256(buf)
    u := bigint.Frombytes(uH[:])

    // Using the given formula for S is too slow to calculate.
    // This version is simplified using modular arithmetic:
    // S = modexp(((A % N) * modexp(v, u, N)) % N, b, N)

    // base = ((A % N) * modexp(v, u, N)) % N
    t1 := new(big.Int).Mod(s.A, N)
    t2 := bigint.Modexp(s.v, u, N)
    t3 := new(big.Int).Mul(t1, t2)
    base := new(big.Int).Mod(t3, N)

    S := bigint.Modexp(base, s.b, N)
    K := sha256.Sum256(S.Bytes())

    return hmacsha256(K[:], s.salt)
}

func (s *Server) Verify(c *Client) bool {
    return bytes.Compare(c.hmac(), s.hmac()) == 0
}

func hmacsha256(key, msg []byte) []byte {
    const blocklen = 64

    if len(key) > blocklen {
        s := sha256.Sum256(key)
        key = s[:]
    }
    for len(key) < blocklen {
        key = append(key, 0)
    }

    outerblock := make([]byte, blocklen)
    for i:=0; i<blocklen; i++ {
        outerblock[i] = key[i] ^ 0x5c
    }

    innerblock := make([]byte, blocklen)
    for i:=0; i<blocklen; i++ {
        innerblock[i] = key[i] ^ 0x36
    }

    innerhash := sha256.New()
    innerhash.Write(innerblock)
    innerhash.Write(msg)

    outerhash := sha256.New()
    outerhash.Write(outerblock)
    outerhash.Write(innerhash.Sum(nil))
    return outerhash.Sum(nil)
}
