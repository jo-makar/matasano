package main

import (
	"../set5/rsa"

	"bytes"
	"crypto/sha1"
	"errors"
	"log"
	"math/big"
)

func main() {
	//
	// Define the sign and verify functions
	//

	// Choosen such that 2**modulusWidth is a perfect cube (for the math later)
	// and 1024 or greater since the problem specifies a 1024-bit signature.
	const modulusWidth = 768 * 3
	if modulusWidth % 3 != 0 || modulusWidth < 1024 {
		log.Panic("invalid modulus width")
	}

	type Pkcs15Sha1 struct {
		BlockSize  int
		Asn1Digest []byte

		Pad   func(hash [sha1.Size]byte) []byte
		Unpad func(sig []byte) ([sha1.Size]byte, error)
	}

	pkcs15 := func(blockSize int) *Pkcs15Sha1 {
		// Taken from RFC 8017: PKCS #1: RSA Crypto. Specs Ver 2.2, Notes: 1 on page 46
		asn1Sha1Digest := []byte{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14}

		if blockSize <= 4 + len(asn1Sha1Digest) + sha1.Size {
			log.Panic("block size too short")
		}

		pkcs15 := Pkcs15Sha1{ BlockSize: blockSize, Asn1Digest: asn1Sha1Digest }

		pkcs15.Pad = func(hash [sha1.Size]byte) []byte {
			var buf bytes.Buffer

			buf.Write([]byte{0x00,0x01})
			for (buf.Len() + 1 + len(pkcs15.Asn1Digest) + sha1.Size) % pkcs15.BlockSize != 0 {
				buf.WriteByte(0xff)
			}
			buf.WriteByte(0x00)

			buf.Write(pkcs15.Asn1Digest)
			buf.Write(hash[:])
			return buf.Bytes()
		}

		pkcs15.Unpad = func(sig []byte) ([sha1.Size]byte, error) {
			var hash [sha1.Size]byte

			if len(sig) % pkcs15.BlockSize != 0 {
				return hash, errors.New("sig not block-sized")
			}

			buf := bytes.NewBuffer(sig)

			readByte := func(x byte) error {
				if b, err := buf.ReadByte(); err != nil {
					return err
				} else if b != x {
					return errors.New("unexpected byte")
				}
				return nil
			}

			if err := readByte(0x00); err != nil {
				return hash, err
			}
			if err := readByte(0x01); err != nil {
				return hash, err
			}
			if err := readByte(0xff); err != nil {
				return hash, err
			}

			for {
				if b, err := buf.ReadByte(); err != nil {
					return hash, err
				} else if b == 0xff {
					// No-op
				} else if b == 0x00 {
					break
				} else {
					return hash, errors.New("unexpected byte")
				}
			}

			asn1Digest := make([]byte, len(pkcs15.Asn1Digest))
			if _, err := buf.Read(asn1Digest); err != nil {
				return hash, err
			}
			if !bytes.Equal(asn1Digest, pkcs15.Asn1Digest) {
				return hash, errors.New("digest mismatch")
			}

			if buf.Len() != sha1.Size {
				return hash, errors.New("incorrect hash size")
			}
			_, err := buf.Read(hash[:])
			return hash, err
		}

		return &pkcs15

	}(modulusWidth/8)

	sign := func(msg []byte, privkey *rsa.PrivKey) []byte {
		hash := sha1.Sum(msg)
		block := pkcs15.Pad(hash)
		x := new(big.Int).SetBytes(block)

		return rsa.Modexp(x, privkey.D, privkey.N).Bytes()
	}

	verifyCorrect := func(msg, sig []byte, pubkey *rsa.PubKey) bool {
		y := new(big.Int).SetBytes(sig)
		x := rsa.Modexp(y, pubkey.E, pubkey.N)

		// This is needed because the padding starts with a zero byte
		// and the conversion between bytes and math/big.Int is big-endian
		xb := x.Bytes()
		if (len(xb) + 1) % pkcs15.BlockSize == 0 {
			xb2 := make([]byte, len(xb)+1)
			copy(xb2[1:len(xb2)], xb[0:len(xb)])
			xb = xb2
		} else {
			log.Panic("unexpected length")
		}

		blockHash, err := pkcs15.Unpad(xb)
		if err != nil {
			return false
		}

		msgHash := sha1.Sum(msg)
		return bytes.Equal(blockHash[:], msgHash[:])
	}

	verifyBroken := func(msg, sig []byte, pubkey *rsa.PubKey) bool {
		y := new(big.Int).SetBytes(sig)
		x := rsa.Modexp(y, pubkey.E, pubkey.N)

		// This is needed because the padding starts with a zero byte
		// and the conversion between bytes and math/big.Int is big-endian
		xb := x.Bytes()
		if (len(xb) + 1) % pkcs15.BlockSize == 0 {
			xb2 := make([]byte, len(xb)+1)
			copy(xb2[1:len(xb2)], xb[0:len(xb)])
			xb = xb2
		} else {
			log.Panic("unexpected length")
		}

		unpadBroken := func(sig []byte) ([sha1.Size]byte, error) {
			var hash [sha1.Size]byte

			if len(sig) % pkcs15.BlockSize != 0 {
				return hash, errors.New("sig not block-sized")
			}

			buf := bytes.NewBuffer(sig)

			readByte := func(x byte) error {
				if b, err := buf.ReadByte(); err != nil {
					return err
				} else if b != x {
					return errors.New("unexpected byte")
				}
				return nil
			}

			if err := readByte(0x00); err != nil {
				return hash, err
			}
			if err := readByte(0x01); err != nil {
				return hash, err
			}
			if err := readByte(0xff); err != nil {
				return hash, err
			}

			for {
				if b, err := buf.ReadByte(); err != nil {
					return hash, err
				} else if b == 0xff {
					// No-op
				} else if b == 0x00 {
					break
				} else {
					return hash, errors.New("unexpected byte")
				}
			}

			asn1Digest := make([]byte, len(pkcs15.Asn1Digest))
			if _, err := buf.Read(asn1Digest); err != nil {
				return hash, err
			}
			if !bytes.Equal(asn1Digest, pkcs15.Asn1Digest) {
				return hash, errors.New("digest mismatch")
			}

			_, err := buf.Read(hash[:])
			return hash, err
		}

		blockHash, err := unpadBroken(xb)
		if err != nil {
			return false
		}

		msgHash := sha1.Sum(msg)
		return bytes.Equal(blockHash[:], msgHash[:])
	}

	msg := []byte("hi mom")
	privkey, pubkey := rsa.KeyPair(modulusWidth)
	if !verifyCorrect(msg, sign(msg, privkey), pubkey) {
		log.Panic("message unverified")
	}
	if !verifyBroken(msg, sign(msg, privkey), pubkey) {
		log.Panic("message unverified")
	}

	//
	// Bleichenbacker's e=3 RSA attack
	//

	var db bytes.Buffer
	db.WriteByte(0x00)
	db.Write(pkcs15.Asn1Digest)
	h := sha1.Sum(msg)
	db.Write(h[:])
	d := new(big.Int).SetBytes(db.Bytes())
	t := db.Len() * 8

	q := 1 + 384 // (Arbitrary) Length of 0x01 0xff ... 0xff in bits
	if 7 + q + t >= modulusWidth {
		log.Panic("insufficient garbage space")
	}

	n := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(t)), nil), d)
	if new(big.Int).Mod(n, big.NewInt(3)).Cmp(big.NewInt(0)) != 0 {
		log.Panic("n % 3 != 0")
	}

	k := modulusWidth
	x := q + t + 15
	a := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64((k-15)/3)), nil)
	// b = n/3 * 2 ** (k - x - 2*(k-15)/3)
	// However k - x - 2*(k-15)/3 < 0 so rearrange:
	// b = (n/3 * 2**k) >> (x + 2*(k-15)/3)
	
	b := new(big.Int).Mul(new(big.Int).Div(n, big.NewInt(3)),
	                      new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(k)), nil))
	b.Rsh(b, uint(x + 2*(k-15)/3))

	fakeSig := new(big.Int).Sub(a, b).Bytes()

	if !verifyBroken(msg, fakeSig, pubkey) {
		log.Panic("fake message unverified")
	}
	if verifyCorrect(msg, fakeSig, pubkey) {
		log.Panic("fake message verified")
	}

	// This is needed because the padding starts with a zero byte
	// and the conversion between bytes and math/big.Int is big-endian
	fb := new(big.Int).Exp(new(big.Int).SetBytes(fakeSig), big.NewInt(3), nil).Bytes()
	if (len(fb) + 1) % pkcs15.BlockSize == 0 {
		fb2 := make([]byte, len(fb)+1)
		copy(fb2[1:len(fb2)], fb[0:len(fb)])
		fb = fb2
	} else {
		log.Panic("unexpected length")
	}

	log.Printf("(decrypted) fake signature: %v", fb)
}
