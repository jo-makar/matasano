package base64

import (
	"fmt"
)

func Decode(src string) ([]byte, error) {
	if len(src) % 4 != 0 {
		return nil, fmt.Errorf("base64: bad length")
	}

	table := make(map[byte]byte)
	for c := byte('A'); c <= 'Z'; c++ { table[c] = c - 'A' }
	for c := byte('a'); c <= 'z'; c++ { table[c] = c - 'a' + 26 }
	for c := byte('0'); c <= '9'; c++ { table[c] = c - 'A' + 52 }
	table['+'] = 62
	table['/'] = 63

	dest := make([]byte, len(src)/4 * 3)

	for i := 0; i < len(src); i+=4 {
		last := i+4 >= len(src)

		a, ok := table[src[i]]
		if !ok {
			return nil, fmt.Errorf("base64: bad char: %#x", src[i])
		}

		b, ok := table[src[i+1]]
		if !ok {
			return nil, fmt.Errorf("base64: bad char: %#x", src[i+1])
		}

		if last && src[i+2:i+4] == "==" {
			var v uint32 = uint32(a)<<18 | uint32(b)<<12

			dest[i/4 * 3] = byte((v & 0xff0000) >> 16)
			dest = dest[:len(dest)-2]

		} else if last && src[i+3] == '=' {
			c, ok := table[src[i+2]]
			if !ok {
				return nil, fmt.Errorf("base64: bad char: %#x", src[i+2])
			}

			var v uint32 = uint32(a)<<18 | uint32(b)<<12 | uint32(c)<<6

			dest[i/4 * 3]     = byte((v & 0xff0000) >> 16)
			dest[i/4 * 3 + 1] = byte((v & 0x00ff00) >> 8)
			dest = dest[:len(dest)-1]

		} else {
			c, ok := table[src[i+2]]
			if !ok {
				return nil, fmt.Errorf("base64: bad char: %#x", src[i+2])
			}

			d, ok := table[src[i+3]]
			if !ok {
				return nil, fmt.Errorf("base64: bad char: %#x", src[i+3])
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

	for i := 0; i < len(src); i+=3 {
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
