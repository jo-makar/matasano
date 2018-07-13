package main

import (
    "./hex"
    "./xor"
    "fmt"
    "log"
)

func main() {
    plain := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal\n"
    key := "ICE"

    cipher, err := xor.Repeat([]byte(plain), []byte(key))
    if err != nil {
        log.Fatal(err)
    }

    if hex.Encode2(cipher) != "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f4f" {
        log.Fatal(fmt.Sprintf("mismatch: %s", hex.Encode2(cipher)))
    }
}
