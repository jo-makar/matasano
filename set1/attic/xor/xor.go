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

func Repeat(src, key []byte) ([]byte, error) {
    if len(key) == 0 {
        return nil, errors.New("xor: empty key")
    }

    dest := make([]byte, len(src))

    for i, j := 0, 0; i < len(dest); i, j = i + 1, (j+1) % len(key) {
        dest[i] = src[i] ^ key[j]
    }

    return dest, nil
}
