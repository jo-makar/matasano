package aes

import (
	"crypto/aes"
	"errors"
)

const BlockSize = 16

func EcbDecrypt(ciphertext, key []byte) ([]byte, error) {
	if len(key) != BlockSize {
		return nil, errors.New("aes: bad key length")
	}
	if len(ciphertext) % BlockSize != 0 {
		return nil, errors.New("aes: bad ciphertext length")
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))

	for i := 0; i < len(ciphertext); i += BlockSize {
		cipher.Decrypt(plaintext[i:i+BlockSize], ciphertext[i:i+BlockSize])
	}

	return plaintext, nil
}

func EcbEncrypt(plaintext, key []byte) ([]byte, error) {
	if len(key) != BlockSize {
		return nil, errors.New("aes: bad key length")
	}
	if len(plaintext) % BlockSize != 0 {
		return nil, errors.New("aes: bad plaintext length")
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext))

	for i := 0; i < len(plaintext); i += BlockSize {
		cipher.Encrypt(ciphertext[i:i+BlockSize], plaintext[i:i+BlockSize])
	}

	return ciphertext, nil
}

func CbcDecrypt(ciphertext, key, iv []byte) ([]byte, error) {
	if len(key) != BlockSize {
		return nil, errors.New("aes: bad key length")
	}
	if len(iv) != BlockSize {
		return nil, errors.New("aes: bad iv length")
	}
	if len(ciphertext) % BlockSize != 0 {
		return nil, errors.New("aes: bad ciphertext length")
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))

	for i := 0; i < len(ciphertext); i += BlockSize {
		cipher.Decrypt(plaintext[i:i+BlockSize], ciphertext[i:i+BlockSize])

		if i == 0 {
			for j := 0; j < BlockSize; j++ {
				plaintext[i+j] ^= iv[j]
			}
		} else {
			for j := 0; j < BlockSize; j++ {
				plaintext[i+j] ^= ciphertext[i-BlockSize+j]
			}
		}
	}

	return plaintext, nil
}

func CbcEncrypt(plaintext, key, iv []byte) ([]byte, error) {
	if len(key) != BlockSize {
		return nil, errors.New("aes: bad key length")
	}
	if len(iv) != BlockSize {
		return nil, errors.New("aes: bad iv length")
	}
	if len(plaintext) % BlockSize != 0 {
		return nil, errors.New("aes: bad plaintext length")
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext))

	for i := 0; i < len(plaintext); i += BlockSize {
		block := make([]byte, BlockSize)

		if i == 0 {
			for j := 0; j < BlockSize; j++ {
				block[j] = plaintext[i+j] ^ iv[j]
			}
		} else {
			for j := 0; j < BlockSize; j++ {
				block[j] = plaintext[i+j] ^ ciphertext[i-BlockSize+j]
			}
		}

		cipher.Encrypt(ciphertext[i:i+BlockSize], block)
	}

	return ciphertext, nil
}
