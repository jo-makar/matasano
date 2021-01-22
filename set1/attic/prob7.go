package main

import (
    "./base64"
    "bufio"
    "crypto/aes"
    "fmt"
    "io"
    "log"
    "os"
    "path/filepath"
    "runtime"
)

func main() {
    _, path, _, _ := runtime.Caller(0)
    file, err := os.Open(filepath.Join(filepath.Dir(path), "prob7.txt"))
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

    ciphertext, err := base64.Decode(encoded)
    if err != nil {
        log.Fatal(err)
    }

    cipher, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
    if err != nil {
        log.Fatal(err)
    }

    plaintext := make([]byte, len(ciphertext))

    for i:=0; i<len(ciphertext); i+=16 {
        cipher.Decrypt(plaintext[i:i+16], ciphertext[i:i+16])
    }

    fmt.Println(plaintext)
    fmt.Println(string(plaintext))
}
