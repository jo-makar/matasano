package main

import (
    "./bigint"
    "./srp"
    "./ssrp"
    "bufio"
    "bytes"
    "crypto/sha256"
    "fmt"
    "io"
    "log"
    "math/big"
    "os"
    "path/filepath"
    "runtime"
    "strings"
)

func main() {
    email, password := "user@host", "secret"

    {
        server := ssrp.NewServer(email, password)
        client := ssrp.NewClient(email, password)

        client.Send(server)
        server.Send(client)

        if !server.Verify(client) {
            log.Fatal("server.Verify(client) failed")
        }
    }

    {
        client := ssrp.NewClient(email, password)
        server := ssrp.NewServer(email, "")

        // Choose B = g and U = 1 so that:
        //     S = B^(a+ux) % N
        //       = g^(a+x) % N
        //       = (g^a * g^x) % N
        //       = ((g^a % N) * (g^x % N)) % N
        //       = (A * (g^x % N)) % N

        server.B = big.NewInt(2)
        server.Salt = make([]byte, 8)
        server.U = big.NewInt(1)

        client.Send(server)
        server.Send(client)

        target := server.Clienthmac(client)

        // Using an English words list to simulate a dictionary attack

        _, path, _, _ := runtime.Caller(0)
        file, err := os.Open(filepath.Join(filepath.Dir(path), "words.txt"))
        if err != nil {
            log.Fatal(err)
        }

        reader := bufio.NewReader(file)
        for {
            line, err := reader.ReadBytes('\n')
            if err != nil {
                if err == io.EOF {
                    break
                }
                log.Fatal(err)
            }
            word := strings.TrimSpace(string(line))

            buf := make([]byte, 0)
            buf = append(append(buf, server.Salt...), []byte(word)...)
            xH := sha256.Sum256(buf)
            x := bigint.Frombytes(xH[:])

            S := new(big.Int).Mul(client.A, bigint.Modexp(ssrp.G, x, ssrp.N))
            S.Mod(S, ssrp.N)
            K := sha256.Sum256(S.Bytes())
            hmac := srp.Hmacsha256(K[:], server.Salt)

            if bytes.Equal(hmac, target) {
                fmt.Printf("Found password: %q\n", word)
                break
            }
        }
    }
}
