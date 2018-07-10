package main

import (
    "encoding/json"
    "io/ioutil"
    "log"
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

    // FIXME STOPPED Calculate a similar set of tables for some input
    //               (This means that maketable of prob3-1.go must be moved to metric/metric.go)
    //               Then use least squares (call func comparetables or perhaps make objecgts)
    //                   against each table and sum values as a metric
    //               The lower the better (ie more similar to each other)

}
