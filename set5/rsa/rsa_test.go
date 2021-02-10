package rsa

import (
	"../rsa"

	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	t.Run("prob39", func(t *testing.T) {
		privkey, pubkey := rsa.KeyPair(256)
		plaintext := []byte("hello world")
		if !bytes.Equal(privkey.Decrypt(pubkey.Encrypt(plaintext)), plaintext) {
			t.Errorf("decrypt failed")
		}
	})
}
