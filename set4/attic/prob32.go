package main

import (
    "errors"
    "fmt"
    "log"
    "net/http"
    "os"
    "sort"
    "time"
)

func main() {
    const siglen = 40

    file := "foo"
    var sig string

    for len(sig) < siglen {
        var bestdur float64
        var bestbyte byte

        for i:=0; i<16; i++ {
            test := sig + fmt.Sprintf("%x", i)

            trials := make([]float64, 0)
            for trial:=0; trial<10; trial++ {
                start := time.Now()

                url := fmt.Sprintf("http://127.0.0.1:8000/prob32?file=%s&signature=%s", file, test)
                resp, err := http.Get(url)
                if err != nil {
                    log.Fatal(err)
                }

                trials = append(trials, float64(time.Since(start)) / 1000000.0)

                if resp.StatusCode == 200 {
                    fmt.Printf("%s Signature found = %s\n", hms(), test)
                    os.Exit(0)
                } else if resp.StatusCode != 403 {
                    log.Fatal(errors.New(fmt.Sprintf("unexpected status code = %d", resp.StatusCode)))
                }

                resp.Body.Close()
            }

            if dur := median(trials); dur > bestdur {
                bestdur = dur
                bestbyte = byte(i)
            }
        }

        sig += fmt.Sprintf("%x", bestbyte)
        fmt.Printf("%s sig = %s\n", hms(), sig)
    }
}

func median(d []float64) float64 {
    sort.Float64s(d)

    if len(d) % 2 == 0 {
        return (d[len(d)/2] + d[len(d)/2-1]) / 2.0
    } else {
        return d[len(d)/2]
    }
}

func hms() string {
    t := time.Now()
    return fmt.Sprintf("%02d:%02d:%02d", t.Hour(), t.Minute(), t.Second())
}
