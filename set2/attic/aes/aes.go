package aes

import (
    "crypto/aes"
    "errors"
)

func Ecbdecrypt(ciphertext, key []byte) ([]byte, error) {
    if len(key) != 16 {
        return nil, errors.New("aes: bad key length")
    }
    if len(ciphertext) % len(key) != 0 {
        return nil, errors.New("aes: bad ciphertext length")
    }

    cipher, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    plaintext := make([]byte, len(ciphertext))

    for i:=0; i<len(ciphertext); i+=len(key) {
        cipher.Decrypt(plaintext[i:i+len(key)], ciphertext[i:i+len(key)])
    }

    return plaintext, nil
}

func Ecbencrypt(plaintext, key []byte) ([]byte, error) {
    if len(key) != 16 {
        return nil, errors.New("aes: bad key length")
    }
    if len(plaintext) % len(key) != 0 {
        return nil, errors.New("aes: bad plaintext length")
    }

    cipher, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    ciphertext := make([]byte, len(plaintext))

    for i:=0; i<len(plaintext); i+=len(key) {
        cipher.Encrypt(ciphertext[i:i+len(key)], plaintext[i:i+len(key)])
    }

    return ciphertext, nil
}

func Cbcdecrypt(ciphertext, key, iv []byte) ([]byte, error) {
    if len(key) != 16 {
        return nil, errors.New("aes: bad key length")
    }
    if len(ciphertext) % len(key) != 0 {
        return nil, errors.New("aes: bad ciphertext length")
    }
    if len(iv) != len(key) {
        return nil, errors.New("aes: bad iv length")
    }

    cipher, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    plaintext := make([]byte, len(ciphertext))

    for i:=0; i<len(ciphertext); i+=len(key) {
        cipher.Decrypt(plaintext[i:i+len(key)], ciphertext[i:i+len(key)])

        for j:=0; j<len(key); j++ {
            if i == 0 {
                plaintext[i+j] ^= iv[j]
            } else {
                plaintext[i+j] ^= ciphertext[i-len(key)+j]
            }
        }
    }

    return plaintext, nil
}

func Cbcencrypt(plaintext, key, iv []byte) ([]byte, error) {
    if len(key) != 16 {
        return nil, errors.New("aes: bad key length")
    }
    if len(plaintext) % len(key) != 0 {
        return nil, errors.New("aes: bad plaintext length")
    }
    if len(iv) != len(key) {
        return nil, errors.New("aes: bad iv length")
    }

    cipher, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    ciphertext := make([]byte, len(plaintext))

    for i:=0; i<len(plaintext); i+=len(key) {
        block := make([]byte, len(key))

        for j:=0; j<len(key); j++ {
            if i == 0 {
                block[j] = plaintext[i+j] ^ iv[j]
            } else {
                block[j] = plaintext[i+j] ^ ciphertext[i-len(key)+j]
            }
        }

        cipher.Encrypt(ciphertext[i:i+len(key)], block)
    }

    return ciphertext, nil
}
