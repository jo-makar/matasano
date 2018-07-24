package main

import (
    "./sha1"
    "../set1/hex"
    "fmt"
    "io"
    "log"
    "net/http"
    "time"
)

func main() {
    http.HandleFunc("/prob32", hmachandler)
    if err := http.ListenAndServe(":8000", nil); err != nil {
        log.Fatal(err)
    }
}

func hmachandler(w http.ResponseWriter, r *http.Request) {
    key := []byte("cIO\\CB@F9u")

    q := r.URL.Query()

    for _, p := range([]string{"file", "signature"}) {
        v, ok := q[p]
        if !ok {
            w.WriteHeader(http.StatusInternalServerError)
            io.WriteString(w, fmt.Sprintf("missing %s param\n", p))
            return
        } else if len(v) > 1 {
            w.WriteHeader(http.StatusInternalServerError)
            io.WriteString(w, fmt.Sprintf("multiple %s params\n", p))
            return
        }
    }

    file := q["file"][0]
    sig := q["signature"][0]

    hmac := hex.Encode2(hmacsha1(key, []byte(file)))
    if insecurecompare(hmac, sig, 5) {
        w.WriteHeader(http.StatusOK)
    } else {
        w.WriteHeader(http.StatusForbidden)
    }
}

func insecurecompare(hmac1, hmac2 string, delayms uint) bool {
    min := len(hmac1)
    if len(hmac2) < min {
        min = len(hmac2)
    }

    for i:=0; i<min; i++ {
        if hmac1[i] != hmac2[i] {
            return false
        }

        // The comparisons are by nibble, halve the delay
        time.Sleep(time.Duration(delayms/2) * time.Millisecond)
    }

    return len(hmac1) == len(hmac2)
}

func hmacsha1(key, msg []byte) []byte {
    const blocklen = 64

    if len(key) > blocklen {
        s := sha1.Sum(key)
        key = s[:]
    }
    for len(key) < blocklen {
        key = append(key, 0)
    }

    outerblock := make([]byte, blocklen)
    for i:=0; i<blocklen; i++ {
        outerblock[i] = key[i] ^ 0x5c
    }

    innerblock := make([]byte, blocklen)
    for i:=0; i<blocklen; i++ {
        innerblock[i] = key[i] ^ 0x36
    }

    innerhash := sha1.New()
    innerhash.Write(innerblock)
    innerhash.Write(msg)

    outerhash := sha1.New()
    outerhash.Write(outerblock)
    outerhash.Write(innerhash.Sum(nil))
    return outerhash.Sum(nil)
}
