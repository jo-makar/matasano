package xor

import "errors"

func Sum(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		errors.New("xor: different lengths")
	}

	rv := make([]byte, len(a))

	for i := 0; i < len(a); i++ {
		rv[i] = a[i] ^ b[i]
	}

	return rv, nil
}

func SumRepeat(a, b []byte) ([]byte, error) {
	if len(b) == 0 {
		return a, nil
	}

	rv := make([]byte, len(a))

	for i, j := 0, 0; i < len(rv); i, j = i+1, (j+1) % len(b) {
		rv[i] = a[i] ^ b[j]
	}

	return rv, nil
}
