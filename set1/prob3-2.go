package main

import (
    "./hex"
    "./score"
    "./xor"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "math"
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

    data, err := hex.Decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    if err != nil {
        log.Fatal(err)
    }

    var lowestscore float32 = math.MaxFloat32
    var lowestchar byte = 0

    for c:=0; c<256; c++ {
        data2, err := xor.Repeat(data, []byte{byte(c)})
        if err != nil {
            log.Fatal(err)
        }

        t1, err := score.Maketable2(data2, 1)
        if err != nil {
            log.Fatal(err)
        }

        t2, err := score.Maketable2(data2, 2)
        if err != nil {
            log.Fatal(err)
        }

        s := score.Comparetables(tables[0], t1) + score.Comparetables(tables[1], t2)
        if s < lowestscore {
            lowestscore = s
            lowestchar = byte(c)
        }
    }

    data2, err := xor.Repeat(data, []byte{lowestchar})
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("best key is 0x%02x producing the output:\n", lowestchar)
    fmt.Println(hex.Encode2(data2))
    fmt.Println(string(data2))
}
