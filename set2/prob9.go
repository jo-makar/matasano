package main

import (
    "./pkcs7"
    "fmt"
    "log"
)

func main() {
    test([]byte("YELLOW SUBMARINE"), []byte("YELLOW SUBMARINE\x04\x04\x04\x04"), 20)

    test([]byte(""),     []byte("\x04\x04\x04\x04"),     4)
    test([]byte("x"),    []byte("x\x03\x03\x03"),        4)
    test([]byte("xx"),   []byte("xx\x02\x02"),           4)
    test([]byte("xxx"),  []byte("xxx\x01"),              4)
    test([]byte("xxxx"), []byte("xxxx\x04\x04\x04\x04"), 4)

    test([]byte("xxxxx"),    []byte("xxxxx\x03\x03\x03"),        4)
    test([]byte("xxxxxx"),   []byte("xxxxxx\x02\x02"),           4)
    test([]byte("xxxxxxx"),  []byte("xxxxxxx\x01"),              4)
    test([]byte("xxxxxxxx"), []byte("xxxxxxxx\x04\x04\x04\x04"), 4)
}

func test(input, expected  []byte, blklen uint) {
    padded, err := pkcs7.Pad(input, blklen)
    if err != nil {
        log.Fatal(err)
    }

    if !equal(padded, expected) {
        log.Fatal(fmt.Sprintf("mismatch: %v", padded))
    }

    unpadded, err := pkcs7.Unpad(padded, blklen)
    if err != nil {
        log.Fatal(err)
    }

    if !equal(unpadded, input) {
        log.Fatal(fmt.Sprintf("mismatch: %v", unpadded))
    }
}

func equal(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }

    for i:=0; i<len(a); i++ {
        if a[i] != b[i] {
            return false
        }
    }

    return true
}
