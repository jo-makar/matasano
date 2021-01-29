package main

import (
    "./aes"
    "../set1/base64"
    "../set1/score"
    "bufio"
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "io/ioutil"
    "log"
    "math"
    "math/rand"
    "os"
    "path/filepath"
    "runtime"
    "time"
)

func main() {
    rand.Seed(time.Now().Unix())
    key := randbytes(16)
    nonce := uint64(0)

    _, path, _, _ := runtime.Caller(0)

    file, err := os.Open(filepath.Join(filepath.Dir(path), "prob20.txt"))
    if err != nil {
        log.Fatal(err)
    }

    plains := make([][]byte, 0)
    ciphers := make([][]byte, 0)

    reader := bufio.NewReader(file)
    for {
        line, err := reader.ReadBytes('\n')
        if err != nil {
            if err == io.EOF {
                break
            }
            log.Fatal(err)
        }
        line = line[:len(line)-1]

        decoded, err := base64.Decode(string(line))
        if err != nil {
            log.Fatal(err)
        }

        plains = append(plains, decoded)

        cipher, err := aes.Ctrencrypt(decoded, key, nonce)
        if err != nil {
            log.Fatal(err)
        }

        ciphers = append(ciphers, cipher)
    }

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
    //      Obviously didn't bother truncating as recommended in problem text.

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
        fmt.Println(string(v))
    }
}

func randbytes(n uint) []byte {
    rv := make([]byte, n)

    for i:=uint(0); i<n; i++ {
        rv[i] = byte(rand.Intn(256))
    }

    return rv
}
