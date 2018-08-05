package main

import (
    "./srp"
    "crypto/sha256"
    "fmt"
    "log"
    "math/big"
)

func main() {
    email, password := "user@host", "secret"
    server := srp.NewServer(email, password)

    {
        client := srp.NewClient(email, password)

        client.Send(server)
        server.Send(client)
        if !server.Verify(client) {
            log.Fatal("server.Verify(client) failed")
        }
    }

    // Setting A = 0 forces S = 0 on the server
    {
        client := srp.NewClient(email, "")
        client.A = big.NewInt(0)

        client.Send(server)
        server.Send(client)

        S := big.NewInt(0)
        K := sha256.Sum256(S.Bytes())
        hmac := srp.Hmacsha256(K[:], client.Salt)

        if !server.Verify2(hmac) {
            log.Fatal("A=0 server.Verify2(hmac) failed")
        }
    }

    // Setting A = N, N*2, ... also forces S = 0 on the server
    for i:=1; i<5; i++ {
        client := srp.NewClient(email, "")
        client.A = new(big.Int).Mul(srp.N, big.NewInt(int64(i)))

        client.Send(server)
        server.Send(client)

        S := big.NewInt(0)
        K := sha256.Sum256(S.Bytes())
        hmac := srp.Hmacsha256(K[:], client.Salt)

        if !server.Verify2(hmac) {
            log.Fatal(fmt.Sprintf("A=N*%d server.Verify2(hmac) failed", i))
        }
    }
}
