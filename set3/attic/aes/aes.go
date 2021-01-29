package aes

import (
    "bytes"
    "crypto/aes"
    "encoding/binary"
    "errors"
)

func Ctrdecrypt(ciphertext, key []byte, nonce uint64) ([]byte, error) {
    if len(key) != 16 {
        return nil, errors.New("aes: unsupported key length")
    }

    cipher, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    plaintext := make([]byte, len(ciphertext))

    for n:=uint64(0); n*uint64(len(key)) < uint64(len(ciphertext)); n++ {
        keystream, err := keystream_aes128(nonce, n)
        if err != nil {
            return nil, err
        }

        enckeystream := make([]byte, len(keystream))
        cipher.Encrypt(enckeystream, keystream)

        var block []byte
        if (n+1)*uint64(len(key)) <= uint64(len(ciphertext)) {
            block = ciphertext[n*uint64(len(key)) : (n+1)*uint64(len(key))]
        } else {
            block = ciphertext[n*uint64(len(key)) : len(ciphertext)]
        }

        for i:=0; i<len(block); i++ {
            plaintext[n*uint64(len(key)) + uint64(i)] = block[i] ^ enckeystream[i]
        }
    }

    return plaintext, nil
}

func Ctrencrypt(plaintext, key []byte, nonce uint64) ([]byte, error) {
    if len(key) != 16 {
        return nil, errors.New("aes: unsupported key length")
    }

    cipher, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    ciphertext := make([]byte, len(plaintext))

    for n:=uint64(0); n*uint64(len(key)) < uint64(len(plaintext)); n++ {
        keystream, err := keystream_aes128(nonce, n)
        if err != nil {
            return nil, err
        }

        enckeystream := make([]byte, len(keystream))
        cipher.Encrypt(enckeystream, keystream)

        var block []byte
        if (n+1)*uint64(len(key)) <= uint64(len(plaintext)) {
            block = plaintext[n*uint64(len(key)) : (n+1)*uint64(len(key))]
        } else {
            block = plaintext[n*uint64(len(key)) : len(plaintext)]
        }

        for i:=0; i<len(block); i++ {
            ciphertext[n*uint64(len(key)) + uint64(i)] = block[i] ^ enckeystream[i]
        }
    }

    return ciphertext, nil
}

func keystream_aes128(nonce, block uint64) ([]byte, error) {
    buf := new(bytes.Buffer)

    err := binary.Write(buf, binary.LittleEndian, nonce)
    if err != nil {
        return nil, err
    }

    err = binary.Write(buf, binary.LittleEndian, block)
    if err != nil {
        return nil, err
    }

    return buf.Bytes(), nil
}
