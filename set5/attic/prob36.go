package main

import (
    "./srp"
    "fmt"
)

func main() {
    email, password := "user@host", "secret"

    {
        client := srp.NewClient(email, password)
        server := srp.NewServer(email, password)

        client.Send(server)
        server.Send(client)
        fmt.Println(server.Verify(client))
    }

    {
        client := srp.NewClient(email, password + "xyz")
        server := srp.NewServer(email, password)

        client.Send(server)
        server.Send(client)
        fmt.Println(server.Verify(client))
    }
}
