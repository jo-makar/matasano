package base64

import (
    "errors"
    "fmt"
)

func Decode(src string) ([]byte, error) {
    if len(src) % 4 != 0 {
        return nil, errors.New("base64: bad length")
    }

    dest := make([]byte, len(src)/4 * 3)

    for i:=0; i<len(src); i+=4 {
        last := i+4 >= len(src)

        a, ok := base64char(src[i])
        if !ok {
            return nil, errors.New(fmt.Sprintf("base64: bad char: %#x", src[i]))
        }

        b, ok := base64char(src[i+1])
        if !ok {
            return nil, errors.New(fmt.Sprintf("base64: bad char: %#x", src[i+1]))
        }

        if last && src[i+2:i+4] == "==" {
            var v uint32 = uint32(a)<<18 | uint32(b)<<12

            dest[i/4 * 3] = byte((v & 0xff0000) >> 16)

            dest = dest[:len(dest)-2]
        } else if last && src[i+3] == '=' {
            c, ok := base64char(src[i+2])
            if !ok {
                return nil, errors.New(fmt.Sprintf("base64: bad char: %#x", src[i+2]))
            }

            var v uint32 = uint32(a)<<18 | uint32(b)<<12 | uint32(c)<<6

            dest[i/4 * 3]     = byte((v & 0xff0000) >> 16)
            dest[i/4 * 3 + 1] = byte((v & 0x00ff00) >> 8)

            dest = dest[:len(dest)-1]
        } else {
            c, ok := base64char(src[i+2])
            if !ok {
                return nil, errors.New(fmt.Sprintf("base64: bad char: %#x", src[i+2]))
            }

            d, ok := base64char(src[i+3])
            if !ok {
                return nil, errors.New(fmt.Sprintf("base64: bad char: %#x", src[i+3]))
            }

            var v uint32 = uint32(a)<<18 | uint32(b)<<12 | uint32(c)<<6 | uint32(d)

            dest[i/4 * 3]     = byte((v & 0xff0000) >> 16)
            dest[i/4 * 3 + 1] = byte((v & 0x00ff00) >> 8)
            dest[i/4 * 3 + 2] = byte( v & 0x0000ff )
        }
    }

    return dest, nil
}

func Encode(src []byte) (string, error) {
    const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    var dest []byte
    if len(src) % 3 == 0 {
        dest = make([]byte, len(src)/3 * 4)
    } else {
        dest = make([]byte, (len(src)/3 + 1) * 4)
    }

    for i:=0; i<len(src); i+=3 {
        j := i + 3
        if len(src) < j {
            j = len(src)
        }

        if j-i == 3 {
            var v uint32 = uint32(src[i])<<16 | uint32(src[i+1])<<8 | uint32(src[i+2])

            dest[i/3 * 4]     = table[(v & 0xfc0000) >> 18]
            dest[i/3 * 4 + 1] = table[(v & 0x03f000) >> 12]
            dest[i/3 * 4 + 2] = table[(v & 0x000fc0) >> 6]
            dest[i/3 * 4 + 3] = table[ v & 0x00003f ]
        } else if j-i == 2 {
            var v uint32 = uint32(src[i])<<16 | uint32(src[i+1])<<8

            dest[i/3 * 4]     = table[(v & 0xfc0000) >> 18]
            dest[i/3 * 4 + 1] = table[(v & 0x03f000) >> 12]
            dest[i/3 * 4 + 2] = table[(v & 0x000fc0) >> 6]
            dest[i/3 * 4 + 3] = '='
        } else {
            var v uint32 = uint32(src[i])<<16

            dest[i/3 * 4]     = table[(v & 0xfc0000) >> 18]
            dest[i/3 * 4 + 1] = table[(v & 0x03f000) >> 12]
            dest[i/3 * 4 + 2] = '='
            dest[i/3 * 4 + 3] = '='
        }
    }

    return string(dest), nil
}

func base64char(c byte) (byte, bool) {
    if 'A' <= c && c <= 'Z' {
        return c-'A', true
    } else if 'a' <= c && c <= 'z' {
        return c-'a'+26, true
    } else if '0' <= c && c <= '9' {
        return c-'0'+52, true
    } else if c == '+' {
        return 62, true
    } else if c == '/' {
        return 63, true
    } else {
        return 0, false
    }
}
