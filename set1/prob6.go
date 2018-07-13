package main

import (
    "./base64"
    "bufio"
    "errors"
    "fmt"
    "io"
    "log"
    "math"
    "os"
    "path/filepath"
    "runtime"
)

func main() {
    // Retrieve and decode the ciphertext

    _, path, _, _ := runtime.Caller(0)
    file, err := os.Open(filepath.Join(filepath.Dir(path), "prob6.txt"))
    if err != nil {
        log.Fatal(err)
    }

    var b64enc string

    reader := bufio.NewReader(file)
    for {
        line, err := reader.ReadBytes('\n')
        if err != nil {
            if err == io.EOF {
                break
            }
            log.Fatal(err)
        }
        line = line[:len(line)-1]

        b64enc += string(line)
    }

    cipher, err := base64.Decode(b64enc)
    if err != nil {
        log.Fatal(err)
    }

    // Guess the keysize using Hamming distance

    var bestdist float32 = math.MaxFloat32
    var bestsize uint

    for i:=uint(2); i<41; i++ {
        chunks := split(cipher, i)

        // Calculate the average distance of first unique pairs

        dists := make([]float32, 50)
        count := 0

        for j:=0; count<len(dists) && j<len(chunks)-1; j++ {
            for k:=j+1; count<len(dists) && k<len(chunks); k, count = k+1, count+1 {
                dists[count] = normdist(chunks[j], chunks[k])
            }
        }

        var avgdist float32
        for _, v := range(dists) {
            avgdist += v
        }
        avgdist /= float32(len(dists))

        if avgdist < bestdist {
            bestdist = avgdist
            bestsize = i
        }
    }

    fmt.Println("best keysize calculated to be", bestsize)

    // Transpose the ciphertext blocks and solve single-char xor against each block

    // FIXME STOPPED
}

// Hamming distance
func dist(a, b []byte) uint {
    if len(a) != len(b) {
        log.Fatal(errors.New("dist: different lengths"))
    }

    var d uint = 0

    for i:=0; i<len(a); i++ {
        v := a[i] ^ b[i]

        for j:=uint(0); j<8; j++ {
            if v & (1<<j) != 0 {
                d++
            }
        }
    }

    return d
}

// Normalized Hamming distance
func normdist(a, b []byte) float32 {
    return float32(dist(a, b)) / float32(len(a))
}

// Split a byte array into n-sized chunks.
// Do not include the final chunk if it less than n bytes.
func split(data []byte, n uint) [][]byte {
    if n == 0 {
        log.Fatal(errors.New("split: n == 0"))
    }
    if n > uint(len(data)) {
        log.Fatal(errors.New("split: n > len(data)"))
    }

    rv := make([][]byte, uint(len(data))/n)

    for i, j := uint(0), 0; i+n <= uint(len(data)); i, j = i+n, j+1 {
        rv[j] = data[i:i+n]
    }

    return rv
}
