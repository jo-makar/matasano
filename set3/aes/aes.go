package aes

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
)

const BlockSize = 16

func CtrDecrypt(ciphertext, key []byte, nonce uint64) ([]byte, error) {
	return CtrEncrypt(ciphertext, key, nonce)
}

func CtrEncrypt(plaintext, key []byte, nonce uint64) ([]byte, error) {
	if len(key) != BlockSize {
		return nil, errors.New("aes: bad key length")
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext))

	keystream := func(nonce, counter uint64) []byte {
		buf := make([]byte, 16)
		binary.LittleEndian.PutUint64(buf[0:8], nonce)
		binary.LittleEndian.PutUint64(buf[8:16], counter)
		return buf
	}

	for counter := uint64(0); counter*BlockSize < uint64(len(plaintext)); counter++ {
		encKeystream := make([]byte, BlockSize)
		cipher.Encrypt(encKeystream, keystream(nonce, counter))

		limit := (counter+1) * BlockSize
		if uint64(len(plaintext)) < limit {
			limit = uint64(len(plaintext))
		}
		for i := counter*BlockSize; i < limit; i++ {
			ciphertext[i] = encKeystream[i%16] ^ plaintext[i]
		}
	}

	return ciphertext, nil
}
