package main

import (
    "./ssrp"
    "log"
)

func main() {
    email, password := "user@host", "secret"
    server := ssrp.NewServer(email, password)

    {
        client := ssrp.NewClient(email, password)

        client.Send(server)
        server.Send(client)

        if !server.Verify(client) {
            log.Fatal("server.Verify(client) failed")
        }
    }
}
