package main

import (
	"./mt19937"

	"fmt"
	"log"
	"math/rand"
	"time"
)

func main() {
	rand.Seed(time.Now().UnixNano())

	origRng := mt19937.NewMt19937Seed(rand.Uint32())

	state := make([]uint32, 624)
	for i := 0; i < len(state); i++ {
		state[i] = mt19937.Untemper(origRng.Uint32())
	}

	splicedRng := mt19937.NewMt19937State(0, state)

	for i := 0; i < 1000; i++ {
		a, b := origRng.Uint32(), splicedRng.Uint32()
		if a != b {
			log.Panic(fmt.Errorf("iteration %d: got %#08x, expected %#08x", i, b, a))
		}
	}

	// To prevent this attack, the state change calculations should be non-invertible.
	// Note that state-to-output calculations could be non-invertible and still be vulnerable.
	// As suggested applying hashes to the output isn't sufficient as that doesn't prevent untempering state. 
}
