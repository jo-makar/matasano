package hex

import "fmt"

func Decode(src string) ([]byte, error) {
	if len(src) % 2 != 0 {
		return nil, fmt.Errorf("hex: bad length")
	}

	table := make(map[byte]byte)
	for c := byte('0'); c <= '9'; c++ { table[c] = c - '0' }
	for c := byte('a'); c <= 'f'; c++ { table[c] = c - 'a' + 10 }
	for c := byte('A'); c <= 'F'; c++ { table[c] = c - 'A' + 10 }

	dest := make([]byte, len(src)/2)

	for i := 0; i < len(src)/2; i++ {
		a, ok := table[src[i*2]]
		if !ok {
			return nil, fmt.Errorf("hex: bad char: %#x", src[i*2])
		}

		b, ok := table[src[i*2+1]]
		if !ok {
			return nil, fmt.Errorf("hex: bad char: %#x", src[i*2+1])
		}

		dest[i] = (a<<4) | b
	}

	return dest, nil
}

func Encode(src []byte) (string, error) {
	const table = "0123456789abcdef"

	dest := make([]byte, len(src)*2)

	for i := 0; i < len(src); i++ {
		dest[i*2]   = table[src[i] >> 4]
		dest[i*2+1] = table[src[i] & 0x0f]
	}

	return string(dest), nil
}
