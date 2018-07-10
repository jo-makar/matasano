package hex

import (
    "errors"
    "fmt"
)

// Decode hex to binary
func Decode(src string) ([]byte, error) {
    if len(src) % 2 != 0 {
        return nil, errors.New("hex: bad length")
    }

    dest := make([]byte, len(src)/2)

    for i:=0; i<len(src)/2; i++ {
        a, ok := hexchar(src[i*2])
        if !ok {
            return nil, errors.New(fmt.Sprintf("hex: bad char: %#x", src[i*2]))
        }

        b, ok := hexchar(src[i*2+1])
        if !ok {
            return nil, errors.New(fmt.Sprintf("hex: bad char: %#x", src[i*2+1]))
        }

        dest[i] = (a<<4) | b
    }

    return dest, nil
}

// Encode binary to hex
func Encode(src []byte) (string, error) {
    const table = "0123456789abcdef"

    dest := make([]byte, len(src)*2)

    for i:=0; i<len(src); i++ {
        dest[i*2] = table[src[i] >> 4]
        dest[i*2+1] = table[src[i] & 0x0f]
    }

    return string(dest), nil
}

func Encode2(src []byte) string {
    rv, _ := Encode(src)
    return rv
}

func hexchar(c byte) (byte, bool) {
    if '0' <= c && c <= '9' {
        return c-'0', true
    } else if 'a' <= c && c <= 'f' {
        return c-'a'+10, true
    } else if 'A' <= c && c <= 'F' {
        return c-'A'+10, true
    } else {
        return 0, false
    }
}
