package main

import (
	"../set5/rsa"

	"bytes"
	"crypto/sha256"
	"errors"
	"log"
	"math/big"
)

func main() {
	//
	// Define the sign and verify functions
	//

	type Pkcs15Sha256 struct {
		BlockSize  int
		asn1Digest []byte

		Pad   func(hash [sha256.Size]byte) []byte
		Unpad func(sig []byte) ([sha256.Size]byte, error)
	}

	pkcs15 := func(blockSize int) *Pkcs15Sha256 {
		// Taken from RFC 8017: PKCS #1: RSA Crypto. Specs Ver 2.2, Notes: 1 on page 46
		asn1Sha256Digest := []byte("\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20")

		if blockSize <= 4 + len(asn1Sha256Digest) + sha256.Size {
			log.Panic("block size too short")
		}

		pkcs15 := Pkcs15Sha256{ BlockSize: blockSize, asn1Digest: asn1Sha256Digest }

		pkcs15.Pad = func(hash [sha256.Size]byte) []byte {
			var buf bytes.Buffer

			buf.Write([]byte{0x00,0x01})
			for (buf.Len() + 1 + len(pkcs15.asn1Digest) + sha256.Size) % pkcs15.BlockSize != 0 {
				buf.WriteByte(0xff)
			}
			buf.WriteByte(0x00)

			buf.Write(pkcs15.asn1Digest)
			buf.Write(hash[:])
			return buf.Bytes()
		}

		pkcs15.Unpad = func(sig []byte) ([sha256.Size]byte, error) {
			var hash [sha256.Size]byte

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

			asn1Digest := make([]byte, len(pkcs15.asn1Digest))
			if _, err := buf.Read(asn1Digest); err != nil {
				return hash, err
			}
			if !bytes.Equal(asn1Digest, pkcs15.asn1Digest) {
				return hash, errors.New("digest mismatch")
			}

			if buf.Len() != sha256.Size {
				return hash, errors.New("incorrect hash size")
			}
			_, err := buf.Read(hash[:])
			return hash, err
		}

		return &pkcs15

	}(100) // Arbitrary choice

	sign := func(msg []byte, privkey *rsa.PrivKey) []byte {
		hash := sha256.Sum256(msg)
		blocks := pkcs15.Pad(hash)
		x := new(big.Int).SetBytes(blocks)

		return rsa.Modexp(x, privkey.D, privkey.N).Bytes()
	}

	verify := func(msg, sig []byte, pubkey *rsa.PubKey) bool {
		y := new(big.Int).SetBytes(sig)
		x := rsa.Modexp(y, pubkey.E, pubkey.N)

		// This is needed because the padding starts with a zero byte
		// and the conversion between bytes and math/big.Int is big-endian
		xb := x.Bytes()
		if (len(xb) + 1) % pkcs15.BlockSize == 0 {
			xb2 := make([]byte, len(xb)+1)
			copy(xb2[1:len(xb2)], xb[0:len(xb)])
			xb = xb2
		}

		blockHash, err := pkcs15.Unpad(xb)
		if err != nil {
			return false
		}

		msgHash := sha256.Sum256(msg)
		return bytes.Equal(blockHash[:], msgHash[:])
	}

	privkey, pubkey := rsa.KeyPair(1024)
	msg := []byte("hi mom")
	if !verify(msg, sign(msg, privkey), pubkey) {
		log.Panic("message unverified")
	}

	//
	// Bleichenbacker's e=3 RSA attack
	//

	// FIXME STOPPED
}
