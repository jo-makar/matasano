package main

import (
    "./hex"
    "./score"
    "./xor"
    "bufio"
    "encoding/json"
    "fmt"
    "io"
    "io/ioutil"
    "log"
    "math"
    "os"
    "path/filepath"
    "runtime"
)

func main() {
    _, path, _, _ := runtime.Caller(0)

    b, err := ioutil.ReadFile(filepath.Join(filepath.Dir(path), "prob3-1.json"))
    if err != nil {
        log.Fatal(err)
    }

    var tables [2]map[string]float32
    err = json.Unmarshal(b, &tables)
    if err != nil {
        log.Fatal(err)
    }

    file, err := os.Open(filepath.Join(filepath.Dir(path), "prob4.txt"))
    if err != nil {
        log.Fatal(err)
    }

    reader := bufio.NewReader(file)

    var lowestscore float32 = math.MaxFloat32
    var lowestchar byte
    var lowestline []byte

    for {
        line, err := reader.ReadBytes('\n')
        if err != nil {
            if err == io.EOF {
                break
            }
            log.Fatal(err)
        }
        line = line[:len(line)-1]

        line2, err := hex.Decode(string(line))
        if err != nil {
            log.Fatal(err)
        }

        for c:=0; c<256; c++ {
            line3, err := xor.Repeat(line2, []byte{byte(c)})
            if err != nil {
                log.Fatal(err)
            }

            t1, err := score.Maketable2(line3, 1)
            if err != nil {
                log.Fatal(err)
            }

            t2, err := score.Maketable2(line3, 2)
            if err != nil {
                log.Fatal(err)
            }

            s := score.Comparetables(tables[0], t1) + score.Comparetables(tables[1], t2)
            if s < lowestscore {
                lowestscore = s
                lowestchar = byte(c)
                lowestline = line2
            }
        }
    }

    lowestline2, err := xor.Repeat(lowestline, []byte{lowestchar})
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("for the input line:\n")
    fmt.Println(hex.Encode2(lowestline))
    fmt.Printf("best key is 0x%02x producing the output:\n", lowestchar)
    fmt.Println(hex.Encode2(lowestline2))
    fmt.Println(string(lowestline2))
}
