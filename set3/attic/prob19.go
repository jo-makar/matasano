package main

import (
    "./aes"
    "../set1/base64"
    "../set1/score"
    "bytes"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "math"
    "math/rand"
    "path/filepath"
    "runtime"
    "time"
)

func main() {
    rand.Seed(time.Now().Unix())
    key := randbytes(16)
    nonce := uint64(0)

    plains := []string{
        "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
        "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
        "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
        "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
        "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
        "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
        "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
        "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
        "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
        "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
        "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
        "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
        "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
        "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
        "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
        "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
        "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
        "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
        "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
        "U2hlIHJvZGUgdG8gaGFycmllcnM/",
        "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
        "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
        "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
        "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
        "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
        "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
        "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
        "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
        "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
        "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
        "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
        "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
        "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
        "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
        "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
        "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
    }

    ciphers := make([][]byte, len(plains))

    for i, v := range plains {
        decoded, err := base64.Decode(v)
        if err != nil {
            log.Fatal(err)
        }

        ciphers[i], err = aes.Ctrencrypt(decoded, key, nonce)
        if err != nil {
            log.Fatal(err)
        }
    }

    _, path, _, _ := runtime.Caller(0)

    data, err := ioutil.ReadFile(filepath.Join(filepath.Dir(path), "../set1/prob3-1.json"))
    if err != nil {
        log.Fatal(err)
    }

    var tables [2]map[string]float32
    err = json.Unmarshal(data, &tables)
    if err != nil {
        log.Fatal(err)
    }

    var maxlen int
    for _, v := range ciphers {
        if len(v) > maxlen {
            maxlen = len(v)
        }
    }

    keystream := make([]byte, maxlen)

    for i:=0; i<len(keystream); i++ {
        // Gather all the bytes xor'ed by the ith byte of the keystream for attack

        buf := new(bytes.Buffer)

        for _, v := range ciphers {
            if i < len(v) {
                buf.WriteByte(v[i])
            }
        }

        // Use metrics on English text to determine which keystream byte is most likely

        var lowestscore float32 = math.MaxFloat32
        var lowestbyte byte

        for j:=0; j<256; j++ {
            test := make([]byte, buf.Len())
            copy(test, buf.Bytes())

            for k:=0; k<len(test); k++ {
                test[k] ^= byte(j)
            }

            table1, err := score.Maketable2(test, 1)
            if err != nil {
                log.Fatal(err)
            }

            s := score.Comparetables(tables[0], table1)
            if s < lowestscore {
                lowestscore = s
                lowestbyte = byte(j)
            }
        }

        keystream[i] = lowestbyte
    }

    // TODO The text used (The Brothers Karamazov.txt) to generate the scoring table is lengthy.
    //      A side effect of this is that lowercase letters are far more common than uppercase,
    //      this skews the probabilities so the first column is incorrect.
    //      This can be fixed by using shorter texts for the scoring table or alternatively using
    //      a different text for sentence beginnings only (not currently bothering though).
    //
    //      Also the last few chars of the longer ciphertexts are incorrect due to lack of data,
    //      this is a more difficult problem algorithmically though can be dealt with in context.

    fmt.Println("Decryptions based on best keystream found:")
    for _, v := range ciphers {
        buf := new(bytes.Buffer)
        for i:=0; i<len(v); i++ {
            buf.WriteByte(v[i] ^ keystream[i])
        }

        fmt.Println(string(buf.Bytes()))
    }

    fmt.Println()
    fmt.Println("Actual plaintext:")
    for _, v := range plains {
        decoded, err := base64.Decode(v)
        if err != nil {
            log.Fatal(err)
        }

        fmt.Println(string(decoded))
    }
}

func randbytes(n uint) []byte {
    rv := make([]byte, n)

    for i:=uint(0); i<n; i++ {
        rv[i] = byte(rand.Intn(256))
    }

    return rv
}
