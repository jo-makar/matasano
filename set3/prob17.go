package main

import (
    "../set1/base64"
    "../set1/xor"
    "../set2/aes"
    "../set2/pkcs7"
    "bytes"
    "fmt"
    "log"
    "math/rand"
    "strings"
    "time"
)

var key []byte

func main() {
    rand.Seed(time.Now().Unix())
    key = randbytes(16)

    for trial:=0; trial<10; trial++ {
        cipher, iv, err := oracle()
        if err != nil {
            log.Fatal(err)
        }

        plain := make([]byte, len(cipher))

        for n:=0; n<len(cipher)/len(key); n++ {
            var decrypted []byte

            // Determine the last byte (potentially bytes) of a ciphertext block
            //
            // In CBC decryption, the ciphertext block is decrypted then xor'ed with the preceding
            // ciphertext block to produce the plaintext block, or in symbolic terms:
            //
            //     Pn = D(Cn) xor Cn-1      where Pn is the nth plaintext block
            //                                    Cn is the nth ciphertext block
            //                              and   D() is the decryption process
            //
            // Create a fake (random) ciphertext block, call it Fn, followed by the target block.
            // If this fake block has valid padding then there are 16 (block length) possibilities:
            //
            //     1st: D(Cn)[15]    xor Fn[15]    == {1}
            //     2nd: D(Cn)[14,15] xor Fn[14,15] == {2,2}
            //     3rd: D(Cn)[13-15] xor Fn[13-15] == {3,3,3}
            //     ...
            //
            // Rearranging terms and using the first formula, the last bytes can now be determined:
            //
            //     1st: Pn[15]    == (Fn[15     xor {1})     xor Cn-1[15]
            //     2nd: Pn[14,15] == (Fn[14,15] xor {2,2})   xor Cn-1[14,15]
            //     3rd: Pn[13-15] == (Fn[13-15] xor {3,3,3}) xor Cn-1[13-15]
            //     ...

            var block0, block1 []byte
            if n == 0 {
                block0 = iv
                block1 = cipher[0:len(key)]
            } else {
                block0 = cipher[(n-1)*len(key) :  n   *len(key)]
                block1 = cipher[ n   *len(key) : (n+1)*len(key)]
            }

            unused := make([]byte, len(key))

            fakeblock0 := make([]byte, len(key))
            copy(fakeblock0, randbytes(uint(len(key))-1))

            for i:=0; i<256; i++ {
                fakeblock0[len(key)-1] = byte(i)

                test := make([]byte, 2*len(key))
                copy(test, fakeblock0)
                copy(test[len(key):2*len(key)], block1)

                valid, err := unoracle(test, unused)
                if err != nil {
                    log.Fatal(err)
                }

                if valid {
                    // Determine the padding by changing one bit from the left side of the block.
                    // The index at which the padding is no longer valid indicates the padding byte.

                    found := false
                    for j:=0; j<len(key); j++ {
                        tmpblock0 := make([]byte, len(key))
                        copy(tmpblock0, fakeblock0)

                        tmpblock0[j] ^= 1

                        test2 := make([]byte, 2*len(key))
                        copy(test2, tmpblock0)
                        copy(test2[len(key):2*len(key)], block1)

                        valid2, err := unoracle(test2, unused)
                        if err != nil {
                            log.Fatal(err)
                        }

                        if !valid2 {
                            b := byte(len(key) - j)

                            decrypted = make([]byte, len(key)-j)

                            for k, l := j, 0; k < len(key); k, l = k+1, l+1 {
                                decrypted[l] = fakeblock0[k] ^ b
                            }

                            found = true
                            break
                        }
                    }

                    // Should never happen
                    if !found {
                        log.Fatal("padding could not be determined")
                    }
                }
            }

            // Should never happen
            if len(decrypted) == 0 {
                log.Fatal("last byte(s) decryption failed")
            }

            // Given at least the last decrypted byte from a ciphertext block, decrypt the remainder.
            // Essentially an extension of the preceding process to find the last decrypted byte(s).

            for len(decrypted) < len(key) {
                b := byte(len(decrypted) + 1)

                found := false
                for i:=0; i<256; i++ {
                    buf := new(bytes.Buffer)

                    buf.Write(randbytes(uint(len(key) - 1 - len(decrypted))))
                    buf.WriteByte(byte(i))

                    for j:=byte(0); j<b-1; j++ {
                        buf.WriteByte(decrypted[j] ^ b)
                    }

                    fakeblock0 = buf.Bytes()

                    test := make([]byte, 2*len(key))
                    copy(test, fakeblock0)
                    copy(test[len(key):2*len(key)], block1)

                    valid, err := unoracle(test, unused)
                    if err != nil {
                        log.Fatal(err)
                    }

                    if valid {
                        decrypted = append([]byte{byte(i) ^ b}, decrypted...)

                        found = true
                        break
                    }
                }

                // Should never happen
                if !found {
                    log.Fatal("previous byte could not be determined")
                }
            }

            plainblock, err := xor.Sum(decrypted, block0)
            if err != nil {
                log.Fatal(err)
            }

            copy(plain[n*len(key) : (n+1)*len(key)], plainblock)
        }

        unpadded, err := pkcs7.Unpad(plain, uint(len(key)))
        if err != nil {
            log.Fatal(err)
        }

        fmt.Printf("Trial %2d: %s\n", trial+1, string(unpadded))
    }
}

func oracle() ([]byte, []byte, error) {
    inputs := []string{
                  "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
                  "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
                  "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
                  "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
                  "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
                  "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
                  "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
                  "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
                  "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
                  "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
              }

    decoded, err := base64.Decode(inputs[rand.Intn(len(inputs))])
    if err != nil {
        return nil, nil, err
    }

    padded, err := pkcs7.Pad(decoded, uint(len(key)))
    if err != nil {
        return nil, nil, err
    }

    iv := randbytes(uint(len(key)))

    cipher, err := aes.Cbcencrypt(padded, key, iv)
    if err != nil {
        return nil, nil, err
    }

    return cipher, iv, nil
}

func unoracle(cipher, iv []byte) (bool, error) {
    padded, err := aes.Cbcdecrypt(cipher, key, iv)
    if err != nil {
        return false, err
    }

    _, err = pkcs7.Unpad(padded, uint(len(key)))
    if err == nil {
        return true, nil
    } else {
        if strings.HasSuffix(err.Error(), "bad padding") {
            return false, nil
        }
        return false, err
    }
}

func randbytes(n uint) []byte {
    rv := make([]byte, n)

    for i:=uint(0); i<n; i++ {
        rv[i] = byte(rand.Intn(256))
    }

    return rv
}
