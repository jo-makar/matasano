package main

import (
    "./base64"
    "./hex"
    "bytes"
    "fmt"
    "log"
)

func main() {
    test("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
         "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")

    encode := func(s string) string {
        hs, _ := hex.Encode([]byte(s))
        return hs
    }

    test(encode("any carnal pleasure."), "YW55IGNhcm5hbCBwbGVhc3VyZS4=")
    test(encode("any carnal pleasure"),  "YW55IGNhcm5hbCBwbGVhc3VyZQ==")
    test(encode("any carnal pleasur"),   "YW55IGNhcm5hbCBwbGVhc3Vy")
    test(encode("any carnal pleasu"),    "YW55IGNhcm5hbCBwbGVhc3U=")
    test(encode("any carnal pleas"),     "YW55IGNhcm5hbCBwbGVhcw==")

    test(encode("pleasure."), "cGxlYXN1cmUu")
    test(encode("leasure."),  "bGVhc3VyZS4=")
    test(encode("easure."),   "ZWFzdXJlLg==")
    test(encode("asure."),    "YXN1cmUu")
    test(encode("sure."),     "c3VyZS4=")
}

func test(hs, b64 string) {
    d1, err := hex.Decode(hs)
    if err != nil {
        log.Fatal(err)
    }

    d2, err := base64.Encode(d1)
    if err != nil {
        log.Fatal(err)
    }

    if d2 != b64 {
        log.Fatal(fmt.Sprintf("%v != %v", d2, b64))
    }

    d3, err := base64.Decode(d2)
    if err != nil {
        log.Fatal(err)
    }

    if !bytes.Equal(d3, d1) {
        log.Fatal(fmt.Sprintf("%v != %v", d3, d1))
    }
}
