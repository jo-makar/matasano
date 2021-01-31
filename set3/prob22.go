package main

import (
	"./mt19937"

	"errors"
	"log"
	"math/rand"
	"time"
)

func main() {
	rand.Seed(time.Now().UnixNano())

	oracle := func() uint32 {
		randSleep := func(min, max uint) {
			n := uint(rand.Intn(int(max-min) + 1)) + min
			time.Sleep(time.Duration(n) * time.Second)
		}

		randSleep(40, 1000)
		rng := mt19937.NewMt19937Seed(uint32(time.Now().Unix()))
		randSleep(40, 1000)
		return rng.Uint32()
	}

	for trial := 0; trial < 5; trial++ {
		target := oracle()
		testSeed := uint32(time.Now().Unix())

		found := false
		for i := 0; i < 4000; i++ {
			if mt19937.NewMt19937Seed(testSeed).Uint32() == target {
				log.Printf("trial %d: seed found after %d tests", trial+1, i+1)
				found = true
				break
			}
			testSeed--
		}

		if !found {
			log.Panic(errors.New("seed not found"))
		}
	}
}
