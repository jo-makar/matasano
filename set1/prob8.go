package main

import (
    "./hex"
    "bufio"
    "bytes"
    "fmt"
    "io"
    "log"
    "os"
    "path/filepath"
    "runtime"
)

func main() {
    _, path, _, _ := runtime.Caller(0)

    file, err := os.Open(filepath.Join(filepath.Dir(path), "prob8.txt"))
    if err != nil {
        log.Fatal(err)
    }

    reader := bufio.NewReader(file)
    linenum := 0

    for {
        line, err := reader.ReadBytes('\n')
        if err != nil {
            if err == io.EOF {
                break
            }
            log.Fatal(err)
        }
        line = line[:len(line)-1]

        linenum += 1

        data, err := hex.Decode(string(line))
        if err != nil {
            log.Fatal(err)
        }

        maxrepeats := 0

        for i:=0; i<len(data); i+=16 {
            repeats := 0

            for j:=0; j<len(data); j+=16 {
                if j == i {
                    continue
                }

                if bytes.Equal(data[i:i+16], data[j:j+16]) {
                    repeats++
                }
            }

            if repeats > maxrepeats {
                maxrepeats = repeats
            }
        }

        if maxrepeats > 0 {
            fmt.Printf("line %d has %d repeated blocks\n", linenum, maxrepeats)
        }
    }
}
