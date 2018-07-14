package main

import (
    "./aes"
    "../set1/base64"
    "bufio"
    "fmt"
    "io"
    "log"
    "os"
    "path/filepath"
    "runtime"
)

func main() {
    _, path, _, _ := runtime.Caller(0)

    file, err := os.Open(filepath.Join(filepath.Dir(path), "prob10.txt"))
    if err != nil {
        log.Fatal(err)
    }

    var encoded string

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

        encoded += string(line)
    }

    cipher, err := base64.Decode(encoded)
    if err != nil {
        log.Fatal(err)
    }

    plain, err := aes.Cbcdecrypt(cipher, []byte("YELLOW SUBMARINE"), []byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0})
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(plain)
    fmt.Println(string(plain))
}
