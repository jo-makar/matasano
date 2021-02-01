package main

import (
    "./rand"
    "./md4"
    "bytes"
    "encoding/binary"
    "errors"
    "fmt"
    "log"
)

func main() {
    key := rand.Bytes2(5, 10)

    msg := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
    mac := macmd4(key, msg)

    // Retrieve the MD4 registers from the MAC

    var regs [4]uint32

    for i:=0; i<len(regs); i++ {
        s := bytes.NewReader(mac[4*i : 4*(i+1)])
        err := binary.Read(s, binary.LittleEndian, &regs[i])
        if err != nil {
            log.Fatal(err)
        }
    }

    found := false
    for keylen:=1; keylen<20; keylen++ {
        // Determine the MD4 padding for the guessed key length

        padding := new(bytes.Buffer)

        padding.WriteByte(0x80)
        for (keylen + len(msg) + padding.Len()) % 64 != 56 {
            padding.WriteByte(0x00)
        }

        l := (uint64(keylen) + uint64(len(msg))) * 8
        err := binary.Write(padding, binary.LittleEndian, &l)
        if err != nil {
            log.Fatal(err)
        }

        // Continue a MD4 calculation with a resumed state

        msg2 := []byte(";admin=true")

        hash := md4.New2(regs, uint64(keylen + len(msg) + padding.Len()))
        hash.Write(msg2)
        forgedmac := hash.Sum(nil)

        // Check if the key length is correct

        b := new(bytes.Buffer)
        b.Write(msg)
        b.Write(padding.Bytes())
        b.Write(msg2)
        if bytes.Equal(forgedmac, macmd4(key, b.Bytes())) {
            fmt.Printf("Key length is %d\n", keylen)
            fmt.Printf("Forged MAC = %v\n", forgedmac)
            found = true
            break
        }
    }

    if !found {
        log.Fatal(errors.New("could not determine key length"))
    }
}

func macmd4(key, msg []byte) []byte {
    hash := md4.New()
    hash.Write(key)
    hash.Write(msg)
    return hash.Sum(nil)
}
