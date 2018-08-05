package ssrp

import (
    "../bigint"
    "../srp"
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
var G = big.NewInt(2)
var k = big.NewInt(3)

type Client struct {
    I, P string
    a, A *big.Int

    Salt []byte
    B *big.Int
    U *big.Int
}

func (c *Client) Init(I, P string) {
    c.I, c.P = I, P

    c.a = bigint.Randintn(N)
    c.A = bigint.Modexp(G, c.a, N)
}

func NewClient(I, P string) *Client {
    c := new(Client)
    c.Init(I, P)
    return c
}

func (c *Client) Send(s *Server) {
    if strings.Compare(c.I, s.I) != 0 {
        log.Fatal("ssrp: I mismatch")
    }

    s.A = c.A
}

func (c *Client) hmac() []byte {
    buf := make([]byte, 0)
    buf = append(append(buf, c.Salt...), []byte(c.P)...)

    xH := sha256.Sum256(buf)
    x := bigint.Frombytes(xH[:])

    exp := new(big.Int).Add(c.a, new(big.Int).Mul(c.U, x))
    S := bigint.Modexp(c.B, exp, N)
    K := sha256.Sum256(S.Bytes())

    return srp.Hmacsha256(K[:], c.Salt)
}

type Server struct {
    I, P string
    b, B *big.Int
    Salt []byte
    v *big.Int
    U *big.Int

    A *big.Int
}

func (s *Server) Init(I, P string) {
    s.I, s.P = I, P

    s.Salt = make([]byte, 8)
    binary.BigEndian.PutUint64(s.Salt, rand.Uint64())

    buf := make([]byte, 0)
    buf = append(append(buf, s.Salt...), []byte(s.P)...)

    xH := sha256.Sum256(buf)
    x := bigint.Frombytes(xH[:])
    s.v = bigint.Modexp(G, x, N)

    s.b = bigint.Randintn(N)
    s.B = bigint.Modexp(G, s.b, N)

    s.U = bigint.Frombytes(rand.Bytes(16))
}

func NewServer(I, P string) *Server {
    s := new(Server)
    s.Init(I, P)
    return s
}

func (s *Server) Send(c *Client) {
    c.Salt = s.Salt
    c.B = s.B
    c.U = s.U
}

func (s *Server) hmac() []byte {
    // Using the given formula for S is too slow to calculate.
    // This version is simplified using modular arithmetic:
    // S = modexp(((A % N) * modexp(v, U, N)) % N, b, N)

    t1 := bigint.Modexp(s.v, s.U, N)
    t2 := new(big.Int).Mod(s.A, N)
    t3 := new(big.Int).Mul(t2, t1)
    base := new(big.Int).Mod(t3, N)
    S := bigint.Modexp(base, s.b, N)
    K := sha256.Sum256(S.Bytes())

    return srp.Hmacsha256(K[:], s.Salt)
}

func (s *Server) Verify(c *Client) bool {
    return bytes.Compare(c.hmac(), s.hmac()) == 0
}

func (s *Server) Verify2(hmac []byte) bool {
    return bytes.Compare(hmac, s.hmac()) == 0
}

func (s *Server) Clienthmac(c *Client) []byte {
    return c.hmac()
}
