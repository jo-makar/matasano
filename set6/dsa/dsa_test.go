package dsa

import (
	"../dsa"

	"math/big"
	"testing"
)

func TestSignVerify(t *testing.T) {
	t.Run("prob43-1", func(t *testing.T) {
		msg := []byte("attack at dawn")
		privkey, pubkey := dsa.KeyPair(1024, 160)
		if sig, _ := dsa.Sign(msg, privkey, pubkey); !sig.Verify(msg, pubkey) {
			t.Errorf("verify failed")
		}
	})

	t.Run("prob43-2", func(t *testing.T) {
		msg := []byte("For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n")
		pubkey := &dsa.PubKey{
			P: new(big.Int).SetBytes([]byte{0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x89, 0xe1, 0x85, 0x52, 0x18, 0xa0, 0xe7, 0xda, 0xc3, 0x81, 0x36, 0xff, 0xaf, 0xa7, 0x2e, 0xda, 0x78, 0x59, 0xf2, 0x17, 0x1e, 0x25, 0xe6, 0x5e, 0xac, 0x69, 0x8c, 0x17, 0x2, 0x57, 0x8b, 0x7, 0xdc, 0x2a, 0x10, 0x76, 0xda, 0x24, 0x1c, 0x76, 0xc6, 0x2d, 0x37, 0x4d, 0x83, 0x89, 0xea, 0x5a, 0xef, 0xfd, 0x32, 0x26, 0xa0, 0x53, 0xc, 0xc5, 0x65, 0xf3, 0xbf, 0x6b, 0x50, 0x92, 0x91, 0x39, 0xeb, 0xea, 0xc0, 0x4f, 0x48, 0xc3, 0xc8, 0x4a, 0xfb, 0x79, 0x6d, 0x61, 0xe5, 0xa4, 0xf9, 0xa8, 0xfd, 0xa8, 0x12, 0xab, 0x59, 0x49, 0x42, 0x32, 0xc7, 0xd2, 0xb4, 0xde, 0xb5, 0xa, 0xa1, 0x8e, 0xe9, 0xe1, 0x32, 0xbf, 0xa8, 0x5a, 0xc4, 0x37, 0x4d, 0x7f, 0x90, 0x91, 0xab, 0xc3, 0xd0, 0x15, 0xef, 0xc8, 0x71, 0xa5, 0x84, 0x47, 0x1b, 0xb1}),
			Q: new(big.Int).SetBytes([]byte{0xf4, 0xf4, 0x7f, 0x5, 0x79, 0x4b, 0x25, 0x61, 0x74, 0xbb, 0xa6, 0xe9, 0xb3, 0x96, 0xa7, 0x70, 0x7e, 0x56, 0x3c, 0x5b}),
			G: new(big.Int).SetBytes([]byte{0x59, 0x58, 0xc9, 0xd3, 0x89, 0x8b, 0x22, 0x4b, 0x12, 0x67, 0x2c, 0xb, 0x98, 0xe0, 0x6c, 0x60, 0xdf, 0x92, 0x3c, 0xb8, 0xbc, 0x99, 0x9d, 0x11, 0x94, 0x58, 0xfe, 0xf5, 0x38, 0xb8, 0xfa, 0x40, 0x46, 0xc8, 0xdb, 0x53, 0x3, 0x9d, 0xb6, 0x20, 0xc0, 0x94, 0xc9, 0xfa, 0x7, 0x7e, 0xf3, 0x89, 0xb5, 0x32, 0x2a, 0x55, 0x99, 0x46, 0xa7, 0x19, 0x3, 0xf9, 0x90, 0xf1, 0xf7, 0xe0, 0xe0, 0x25, 0xe2, 0xd7, 0xf7, 0xcf, 0x49, 0x4a, 0xff, 0x1a, 0x4, 0x70, 0xf5, 0xb6, 0x4c, 0x36, 0xb6, 0x25, 0xa0, 0x97, 0xf1, 0x65, 0x1f, 0xe7, 0x75, 0x32, 0x35, 0x56, 0xfe, 0x0, 0xb3, 0x60, 0x8c, 0x88, 0x78, 0x92, 0x87, 0x84, 0x80, 0xe9, 0x90, 0x41, 0xbe, 0x60, 0x1a, 0x62, 0x16, 0x6c, 0xa6, 0x89, 0x4b, 0xdd, 0x41, 0xa7, 0x5, 0x4e, 0xc8, 0x9f, 0x75, 0x6b, 0xa9, 0xfc, 0x95, 0x30, 0x22, 0x91}),
			Y: new(big.Int).SetBytes([]byte{0x8, 0x4a, 0xd4, 0x71, 0x9d, 0x4, 0x44, 0x95, 0x49, 0x6a, 0x32, 0x1, 0xc8, 0xff, 0x48, 0x4f, 0xeb, 0x45, 0xb9, 0x62, 0xe7, 0x30, 0x2e, 0x56, 0xa3, 0x92, 0xae, 0xe4, 0xab, 0xab, 0x3e, 0x4b, 0xde, 0xbf, 0x29, 0x55, 0xb4, 0x73, 0x60, 0x12, 0xf2, 0x1a, 0x8, 0x8, 0x40, 0x56, 0xb1, 0x9b, 0xcd, 0x7f, 0xee, 0x56, 0x4, 0x8e, 0x0, 0x4e, 0x44, 0x98, 0x4e, 0x2f, 0x41, 0x17, 0x88, 0xef, 0xdc, 0x83, 0x7a, 0xd, 0x2e, 0x5a, 0xbb, 0x7b, 0x55, 0x50, 0x39, 0xfd, 0x24, 0x3a, 0xc0, 0x1f, 0xf, 0xb2, 0xed, 0x1d, 0xec, 0x56, 0x82, 0x80, 0xce, 0x67, 0x8e, 0x93, 0x18, 0x68, 0xd2, 0x3e, 0xb0, 0x95, 0xfd, 0xe9, 0xd3, 0x77, 0x91, 0x91, 0xb8, 0xc0, 0x29, 0x9d, 0x6e, 0x7, 0xbb, 0xb2, 0x83, 0xe6, 0x63, 0x34, 0x51, 0xe5, 0x35, 0xc4, 0x55, 0x13, 0xb2, 0xd3, 0x3c, 0x99, 0xea, 0x17}),
		}
		sig := &dsa.Signature{
			R: new(big.Int).SetBytes([]byte{0x60, 0x1, 0x9c, 0xac, 0xdc, 0x56, 0xee, 0xdf, 0x8e, 0x8, 0x9, 0x84, 0xbf, 0xa8, 0x98, 0xc8, 0xc5, 0xc4, 0x19, 0xa8}),
			S: new(big.Int).SetBytes([]byte{0x96, 0x1f, 0x20, 0x62, 0xef, 0xc3, 0xc6, 0x8d, 0xb9, 0x65, 0xa9, 0xc, 0x92, 0x4c, 0xf7, 0x65, 0x80, 0xec, 0x1b, 0xbc}),
		}
		if !sig.Verify(msg, pubkey) {
			t.Errorf("verify failed")
		}
	})
}
