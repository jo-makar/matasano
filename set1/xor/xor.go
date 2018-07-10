package xor

import "errors"

func Sum(a, b []byte) ([]byte, error) {
    if len(a) != len(b) {
        return nil, errors.New("xor: different lengths")
    }

    dest := make([]byte, len(a))

    for i:=0; i<len(a); i++ {
        dest[i] = a[i] ^ b[i]
    }

    return dest, nil
}
