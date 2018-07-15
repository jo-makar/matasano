package main

import (
    "./hex"
    "./xor"
    "errors"
    "fmt"
    "log"
)

func main() {
    a, err := hex.Decode("1c0111001f010100061a024b53535009181c")
    if err != nil {
        log.Fatal(err)
    }

    b, err := hex.Decode("686974207468652062756c6c277320657965")
    if err != nil {
        log.Fatal(err)
    }

    c, err := xor.Sum(a, b)
    if err != nil {
        log.Fatal(err)
    }

    c2, err := hex.Encode(c)
    if err != nil {
        log.Fatal(err)
    }
    if c2 != "746865206b696420646f6e277420706c6179" {
        log.Fatal(errors.New(fmt.Sprintf("mismatch: %s", c2)))
    }
}
