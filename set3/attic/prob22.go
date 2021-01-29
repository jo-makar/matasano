package main

import (
    "./mt19937"
    "errors"
    "fmt"
    "log"
    "math/rand"
    "time"
)

func main() {
    rand.Seed(time.Now().Unix())

    for i:=0; i<5; i++ {
        first := oracle()

        // Search backwards by at most 2x of random sleep time
        seed := uint32(time.Now().Unix())

        var j int
        for j=0; j<3000; j++ {
            rng := mt19937.NewMt19937(seed)
            if rng.Rand() == first {
                fmt.Printf("%s trial %d: seed found after %d tests\n", hms(), i+1, j+1)
                break
            }

            seed--
        }

        // Should never happen
        if j == 3000 {
            log.Fatal(errors.New("seed not found"))
        }
    }
}

func oracle() uint32 {
    randsleep(40, 1000)
    seed := time.Now().Unix()

    rng := mt19937.NewMt19937(uint32(seed))

    randsleep(40, 1000)
    return rng.Rand()
}

func randsleep(min, max uint) {
    n := uint(rand.Intn(int((max - min) + 1))) + min
    time.Sleep(time.Duration(n) * time.Second)
}

func hms() string {
    t := time.Now()
    return fmt.Sprintf("%02d:%02d:%02d", t.Hour(), t.Minute(), t.Second())
}
