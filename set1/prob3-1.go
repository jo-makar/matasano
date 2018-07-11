package main

import (
    "./score"
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

    table1, err := score.Maketable(txtfile, 1)
    if err != nil {
        log.Fatal(err)
    }

    table2, err := score.Maketable(txtfile, 2)
    if err != nil {
        log.Fatal(err)
    }

    tables := [2]map[string]float32{table1, table2}

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
