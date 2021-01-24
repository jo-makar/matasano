package main

import (
    "./pkcs7"
    "bytes"
    "errors"
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

    if !bytes.Equal(padded, expected) {
        log.Fatal(errors.New(fmt.Sprintf("mismatch: %v", padded)))
    }

    unpadded, err := pkcs7.Unpad(padded, blklen)
    if err != nil {
        log.Fatal(err)
    }

    if !bytes.Equal(unpadded, input) {
        log.Fatal(errors.New(fmt.Sprintf("mismatch: %v", unpadded)))
    }
}
