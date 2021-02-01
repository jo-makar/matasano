package main

import (
    "./rand"
    "../set2/aes"
    "../set2/pkcs7"
    "bytes"
    "errors"
    "fmt"
    "log"
    "strconv"
    "strings"
)

var key, iv []byte

func main() {
    key = rand.Bytes(16)
    iv = make([]byte, len(key))
    copy(iv, key)

    ciphertext, err := oracle([]byte("foo"))
    if err != nil {
        log.Fatal(err)
    }

    buf := new(bytes.Buffer)
    buf.Write(ciphertext[0:len(key)])
    for i:=0; i<len(key); i++ {
        buf.WriteByte(0)
    }
    buf.Write(ciphertext[0:len(key)])

    // Add the remaining blocks since the last will have valid padding
    buf.Write(ciphertext[3*len(key):])

    success := false
    _, err = unoracle(buf.Bytes())
    if err != nil {
        if strings.HasPrefix(err.Error(), "high ascii: ") {
            var plaintext []byte

            s := strings.Split(err.Error()[13 : len(err.Error())-1], " ")
            for _, v := range s {
                i, err := strconv.Atoi(v)
                if err != nil {
                    log.Fatal(err)
                }
                plaintext = append(plaintext, byte(i))
            }

            recovered := make([]byte, len(key))
            for i:=0; i<len(key); i++ {
                recovered[i] = plaintext[i] ^ plaintext[i+2*len(key)]
            }

            if !bytes.Equal(recovered, key) {
                log.Fatal(errors.New(fmt.Sprintf("%v != %v", recovered, key)))
            }
            success = true
        } else {
            log.Fatal(err)
        }
    }

    if !success {
        log.Fatal(errors.New("not successful"))
    }
}

func oracle(input []byte) ([]byte, error) {
    buf := new(bytes.Buffer)

    buf.WriteString("comment1=cooking%20MCs;userdata=")

    buf.Write(bytes.Replace(
                  bytes.Replace(input, []byte{';'}, []byte{'%','3','b'}, -1),
                                       []byte{'='}, []byte{'%','3','d'}, -1))

    buf.WriteString(";comment2=%20like%20a%20pound%20of%20bacon")

    padded, err := pkcs7.Pad(buf.Bytes(), uint(len(key)))
    if err != nil {
        return nil, err
    }

    ciphertext, err := aes.Cbcencrypt(padded, key, iv)
    if err != nil {
        return nil, err
    }

    return ciphertext, nil
}

func unoracle(input []byte) (bool, error) {
    padded, err := aes.Cbcdecrypt(input, key, iv)
    if err != nil {
        return false, err
    }

    plaintext, err := pkcs7.Unpad(padded, uint(len(key)))
    if err != nil {
        return false, err
    }

    for _, v := range plaintext {
        if v > 0x7f {
            return false, errors.New(fmt.Sprintf("high ascii: %v", plaintext))
        }
    }

    return bytes.Contains(plaintext, []byte(";admin=true;")), nil
}
