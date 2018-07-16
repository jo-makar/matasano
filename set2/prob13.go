package main

import (
    "./aes"
    "./pkcs7"
    "errors"
    "fmt"
    "log"
    "strings"
    "math/rand"
    "time"
)

var key []byte

func main() {
    rand.Seed(time.Now().Unix())
    key = randbytes(16)

    // Stage one, arrange for the first n blocks to be: email=<user>+<junk>@<domain>&uid=10&role=
    // Typically <user>+<junk>@<domain> will be treated as <user>@<domain>

    // email=foo+a@bar.baz&uid=10&role= is exactly 32 bytes
    cipher1, err := oracle("foo+a@bar.com")
    if err != nil {
        log.Fatal(err)
    }

    // Stage two, arrange for the second block to be: admin<padding> via
    // email=<junk>     admin<padding>      &uid=10&role=user<padding>
    // first block      second block        third block

    // email=6789abcdefadmin<-padding->
    // <--  block 1 --><--  block 2 -->
    cipher2, err := oracle("6789abcdefadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b")
    if err != nil {
        log.Fatal(err)
    }

    fake := make([]byte, 48)
    copy(fake, cipher1[0:32])
    copy(fake[32:48], cipher2[16:32])

    fakemap, err := parse(fake)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(fakemap)
}

func randbytes(n uint) []byte {
    rv := make([]byte, n)

    for i:=uint(0); i<n; i++ {
        rv[i] = byte(rand.Intn(256))
    }

    return rv
}

func kvparse(input string) map[string]string {
    // Golang does not support regex negative lookahead grouping for performance
    // ie cannot use regexp.MustCompile("&(?!amp;)").Split(input, -1)

    rv := make(map[string]string)
    t1 := strings.Split(input, "&")

    for _, v := range(t1) {
        t2 := strings.SplitN(v, "=", 2)
        rv[t2[0]] = t2[1]
    }

    return rv
}

func oracle(email string) ([]byte, error) {
    if strings.Contains(email, "&") {
        return nil, errors.New("unallowed character")
    }
    if strings.Contains(email, "=") {
        return nil, errors.New("unallowed character")
    }

    profile := fmt.Sprintf("email=%s&uid=10&role=user", email)

    padded, err := pkcs7.Pad([]byte(profile), uint(len(key)))
    if err != nil {
        return nil, err
    }

    cipher, err := aes.Ecbencrypt(padded, key)
    if err != nil {
        return nil, err
    }

    return cipher, nil
}

func parse(cipher []byte) (map[string]string, error) {
    padded, err := aes.Ecbdecrypt(cipher, key)
    if err != nil {
        return nil, err
    }

    plain, err := pkcs7.Unpad(padded, uint(len(key)))
    if err != nil {
        return nil, err
    }

    return kvparse(string(plain)), nil
}
