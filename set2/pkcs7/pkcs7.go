package pkcs7

import (
	"errors"
	"fmt"
)

func Pad(input []byte, size uint) ([]byte, error) {
	if !(1 < size && size < 256) {
		return nil, errors.New("pkcs7: invalid size")
	}

	// If the input ends at a block boundary a block of padding is appended.
	// This ensures padding can be later removed unambiguously.

	n := size - (uint(len(input)) % size)

	output := make([]byte, uint(len(input)) + n)

	copy(output, input)
	for i := len(input); i < len(output); i++ {
		output[i] = byte(n)
	}

	return output, nil
}

func Unpad(input []byte, size uint) ([]byte, error) {
	if !(1 < size && size < 256) {
		return nil, errors.New("pkcs7: invalid size")
	}
	if len(input) == 0 {
		return nil, errors.New("pkcs7: len(input) == 0")
	}
	if uint(len(input)) % size != 0 {
		return nil, errors.New("pkcs7: len(input) % size != 0")
	}

	b := uint(input[len(input)-1])
	if b == 0 || b > size {
		return nil, fmt.Errorf("pkcs7: bad padding (%#x at %d)", b, len(input)-1)
	}

	for i := uint(len(input)) - b; i < uint(len(input)); i++ {
		if input[i] != byte(b) {
			return nil, fmt.Errorf("pkcs7: bad padding (%#x at %d)", b, i)
		}
	}

	return input[:uint(len(input))-b], nil
}
