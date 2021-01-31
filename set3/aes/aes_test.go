package aes

import (
	"../aes"
	"../../set1/base64"

	"testing"
)

func TestCtrDecrypt(t *testing.T) {
	t.Run  ("prob18", func(t *testing.T) {
		ciphertext, err := base64.Decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
		if err != nil {
			t.Fatal(err)
		}
		key := []byte("YELLOW SUBMARINE")
		nonce := uint64(0)

		if plaintext, err := aes.CtrDecrypt(ciphertext, key, nonce); err != nil {
			t.Fatal(err)
		} else {
			t.Logf("%q", plaintext)
		}
	})
}
