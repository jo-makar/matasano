package score

import (
    "../hex"
    "bytes"
    "errors"
    "os"
)

// Make a table of n-length (hex) strings to occurrence percentage.
// Intended to be used to indicate probablities of string occurrences.
//
// Cannot use slices as map keys (prefer byte slice to string here).
// Also encode as hex for the key to avoid unicode interpretation.
func Maketable(file *os.File, n uint) (map[string]float32, error) {
    if n == 0 {
        return nil, errors.New("maketable: n == 0")
    }

    _, err := file.Seek(0, 0)
    if err != nil {
        return nil, err
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
            return nil, err
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

    return table, nil
}

func Maketable2(data []byte, n uint) (map[string]float32, error) {
    if n == 0 {
        return nil, errors.New("maketable: n == 0")
    }

    table := make(map[string]float32)

    for i:=0; i+int(n) <= len(data); i++ {
        key := hex.Encode2(data[i:i+int(n)])

        _, ok := table[key]
        if !ok {
            table[key] = 0
        }
        table[key] += 1
    }

    var total float32 = 0
    for _, v := range table {
        total += v
    }

    for k, v := range table {
        table[k] = v / total
    }

    return table, nil
}

func Comparetables(table1, table2 map[string]float32) float32 {
    union := map[string]bool{}

    for k, _ := range table1 {
        union[k] = true
    }
    for k, _ := range table2 {
        union[k] = true
    }

    var s float32 = 0

    for k, _ := range union {
        _, ok1 := table1[k]
        _, ok2 := table2[k]

        var r float32
        if !ok1 {
            r = 0 - table2[k]
        } else if !ok2 {
            r = table1[k] - 0
        } else {
            r = table1[k] - table2[k]
        }

        s += r * r
    }

    return s
}
