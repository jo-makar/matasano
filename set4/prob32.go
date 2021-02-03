package main

import (
	"./sha1"
	"../set1/hex"

	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"
)

func main() {
	go func() {
		//
		// Define the HMAC-SHA1 function and web handler
		//

		rand.Seed(time.Now().UnixNano())
		randBytes := func(n uint) []byte {
			b := make([]byte, n)
			rand.Read(b)
			return b
		}

		hmacKey := randBytes(10)

		hmacSha1 := func(msg []byte) [sha1.Size]byte {
			keyPrime := make([]byte, len(hmacKey))
			copy(keyPrime, hmacKey)

			if len(keyPrime) > sha1.BlockSize {
				s := sha1.Sum(keyPrime)
				keyPrime = s[:]
			}
			if len(keyPrime) < sha1.BlockSize {
				keyPrime = append(keyPrime, make([]byte, sha1.BlockSize-len(keyPrime))...)
			}

			paddingBlock := func(b byte) [sha1.BlockSize]byte {
				var block [sha1.BlockSize]byte
				for i := 0; i < len(block); i++ {
					block[i] = b
				}
				return block
			}

			outerPad := paddingBlock(0x5c)
			innerPad := paddingBlock(0x36)

			outerBlock := make([]byte, sha1.BlockSize)
			for i := 0; i < len(outerBlock); i++ {
				outerBlock[i] = keyPrime[i] ^ outerPad[i]
			}

			innerBlock := make([]byte, sha1.BlockSize)
			for i := 0; i < len(innerBlock); i++ {
				innerBlock[i] = keyPrime[i] ^ innerPad[i]
			}
			innerBlock = append(innerBlock, msg...)

			s := sha1.Sum(innerBlock)
			outerBlock = append(outerBlock, s[:]...)
			return sha1.Sum(outerBlock)
		}

		server := http.Server{ Addr: ":8000" }

		http.HandleFunc("/prob32", func(w http.ResponseWriter, r *http.Request) {
			query := r.URL.Query()
			file, sig := query.Get("file"), query.Get("sig")

			if file == "" || sig == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			insecureCompare := func(s, t []byte, delay uint) bool {
				min := len(s)
				if len(t) < min {
					min = len(t)
				}

				for i := 0; i < min; i++ {
					if s[i] != t[i] {
						return false
					}

					// Each loop iteration checks a nibble, hence halving the delay
					time.Sleep(time.Duration(delay/2) * time.Millisecond)
				}

				return len(s) == len(t)
			}


			hmac := hmacSha1([]byte(file))
			hexHmac, _ := hex.Encode(hmac[:])
			if insecureCompare([]byte(sig), []byte(hexHmac), 5) {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusForbidden)
			}
		})

		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			s := <-sigchan
			log.Printf("terminating signal (%d) received", s)
			server.Close()
		}()

		if err := server.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				log.Panic(err)
			}
		}
	}()

	//
	// Use the timing leak to identify a valid MAC
	//

	// Give the other goroutine time to start the http handler
	time.Sleep(1 * time.Second)

	file := "foo"
	var sig string

	out:
	for len(sig) < sha1.Size * 2 {
		var bestByte byte
		var bestTrial float64

		for i := 0; i < 16; i++ {
			testSig := sig + fmt.Sprintf("%x", i)

			trials := make([]time.Duration, 100)
			for j := 0; j < len(trials); j++ {
				start := time.Now()

				url := fmt.Sprintf("http://127.0.0.1:8000/prob32?file=%s&sig=%s", file, testSig)
				resp, err := http.Get(url)
				if err != nil {
					log.Panic(err)
				}

				trials[j] = time.Since(start)

				if resp.StatusCode == 200 {
					log.Printf("signature found: %s", testSig)
					break out
				} else if resp.StatusCode != 403 {
					log.Panic(fmt.Errorf("unexpected status code %d", resp.StatusCode))
				}

				resp.Body.Close()
 			}

			var median float64
 			sort.Slice(trials, func(i, j int) bool { return trials[i] < trials[j] })
 			if len(trials) % 2 == 0 {
	 			median = float64(trials[len(trials)/2] + trials[len(trials)/2-1]) / 2.0
 			} else {
	 			median = float64(trials[len(trials)/2])
 			}

 			if median > bestTrial {
	 			bestByte, bestTrial = byte(i), median
 			}
		}

		sig += fmt.Sprintf("%x", bestByte)
		log.Printf("signature thus far: %s", sig)
	}
}
