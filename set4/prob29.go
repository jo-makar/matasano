package main

import (
	"./sha1"

	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"math/rand"
	"time"
)

func main() {
	//
	// Define the SHA1-MAC functions
	//

	rand.Seed(time.Now().UnixNano())
	randBytes := func(n uint) []byte {
		b := make([]byte, n)
		rand.Read(b)
		return b
	}

	key := randBytes(uint(10 + rand.Intn(11)))

	makeSha1Mac := func(msg []byte) []byte {
		hash := sha1.New()
		hash.Write(key)
		hash.Write(msg)
		return hash.Sum(nil)
	}

	validateSha1Mac := func(mac []byte, msg []byte) bool {
		hash := sha1.New()
		hash.Write(key)
		hash.Write(msg)
		return bytes.Equal(hash.Sum(nil), mac)
	}

	origMsg := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	origMac := makeSha1Mac(origMsg)
	origMacRegs := sha1.ExtractState(origMac)

	//
	// Forge a postfixed message
	//

	// Guess the key length and add the SHA1 padding that would normally occur.
	// Calculate the MAC and extract the resulting SHA1 registers from it.
	// Use the registers in a new SHA1 instance and postfix additional data.

	forgedMsgPostfix := []byte(";admin=true")

	found := false
	for keyLen := 1; keyLen <= 100; keyLen++ {
		var padding bytes.Buffer

		padding.WriteByte(0x80)
		for (keyLen + len(origMsg) + padding.Len()) % 64 != 56 {
			padding.WriteByte(0x00)
		}

		l := uint64(keyLen + len(origMsg)) * 8
		if err := binary.Write(&padding, binary.BigEndian, l); err != nil {
			log.Panic(err)
		}

		hash := sha1.NewState(origMacRegs, uint64(keyLen + len(origMsg) + padding.Len()))
		hash.Write(forgedMsgPostfix)
		forgedMac := hash.Sum(nil)

		var forgedMsg bytes.Buffer
		forgedMsg.Write(origMsg)
		forgedMsg.Write(padding.Bytes())
		forgedMsg.Write(forgedMsgPostfix)

		if validateSha1Mac(forgedMac, forgedMsg.Bytes()) {
			log.Printf("key length is %d", keyLen)
			log.Printf("forged mac = %v", forgedMac)
			found = true
			break
		}
	}

	if !found {
		log.Panic(errors.New("key length undetermined"))
	}
}
