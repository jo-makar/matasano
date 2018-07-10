package main

import (
    "./hex"
    "bytes"
    "encoding/json"
    "log"
    "os"
    "path/filepath"
    "runtime"
)

func main() {
    _, path, _, _ := runtime.Caller(0)
    txtfile, err := os.Open(filepath.Join(filepath.Dir(path), "The Brothers Karamazov.txt"))
    if err != nil {
        log.Fatal(err)
    }

    tables := [2]map[string]float32{maketable(txtfile, 1), maketable(txtfile, 2)}

    base, ext := filepath.Base(path), filepath.Ext(path)
    jsonpath := filepath.Join(filepath.Dir(path), base[:len(base)-len(ext)] + ".json")

    b, err := json.MarshalIndent(tables, "", "  ")
    if err != nil {
        log.Fatal(err)
    }

    jsonfile, err := os.Create(jsonpath)
    if err != nil {
        log.Fatal(err)
    }

    _, err = jsonfile.Write(b)
    if err != nil {
        log.Fatal(err)
    }

    err = jsonfile.Close()
    if err != nil {
        log.Fatal(err)
    }

}

// Make a table of n-length (hex) strings to occurrence percentage in file.
// Intended to be used to indicate probablities of string occurrences in general.
//
// Cannot use slices as map keys (prefer byte slice to string here).
// Also encode as hex for the key to avoid unicode interpretation.
func maketable(file *os.File, n uint) map[string]float32 {
    if n == 0 {
        log.Fatal("maketable: n == 0")
    }

    _, err := file.Seek(0, 0)
    if err != nil {
        log.Fatal(err)
    }

    table := make(map[string]float32)

    key := new(bytes.Buffer)
    b := make([]byte, 1)

    for {
        count, err := file.Read(b)
        if count == 0 {
            break
        }
        if err != nil {
            log.Fatal(err)
        }

        if uint(key.Len()) < 2*n {
            key.WriteString(hex.Encode2(b))
            if uint(key.Len()) < 2*n {
                continue
            }
        } else {
            key = bytes.NewBuffer(key.Bytes()[2:])
            key.WriteString(hex.Encode2(b))
        }

        _, ok := table[key.String()]
        if !ok {
            table[key.String()] = 0
        }
        table[key.String()] += 1
    }

    var total float32 = 0
    for _, v := range table {
        total += v
    }

    for k, v := range table {
        table[k] = v / total
    }

    return table
}
