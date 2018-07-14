package pkcs7

import (
    "errors"
)

func Pad(input []byte, blklen uint) ([]byte, error) {
    if blklen <= 1 {
        return nil, errors.New("Pad: blklen <= 1")
    }

    // The RFC states n >= 256 requires further study
    if blklen >= 256 {
        return nil, errors.New("Pad: blklen >= 256")
    }

    // If the input ends at a block boundary a block of padding is appended.
    // This ensures padding can be later removed unambiguously.

    n := blklen - (uint(len(input)) % blklen)
    b := byte(n)

    rv := make([]byte, uint(len(input)) + n)

    copy(rv, input)
    for i:=uint(len(input)); i<uint(len(rv)); i++ {
        rv[i] = b
    }

    return rv, nil
}

func Unpad(input []byte, blklen uint) ([]byte, error) {
    if len(input) == 0 {
        return nil, errors.New("Unpad: len(input) == 0")
    }
    if uint(len(input)) % blklen != 0 {
        return nil, errors.New("Unpad: len(input) % blklen != 0")
    }

    if blklen <= 1 {
        return nil, errors.New("Unpad: blklen <= 1")
    }

    // The RFC states n >= 256 requires further study
    if blklen >= 256 {
        return nil, errors.New("Unpad: blklen >= 256")
    }

    b := input[len(input)-1]
    n := uint(b)

    if n == 0 || n > blklen {
        return nil, errors.New("Unpad: bad padding")
    }

    for i:=uint(len(input))-n; i<uint(len(input)); i++ {
        if input[i] != b {
            return nil, errors.New("Unpad: bad padding")
        }
    }

    return input[0:uint(len(input))-n], nil
}
