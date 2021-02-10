package main

import (
	"../set5/rsa"

	"bytes"
	"crypto/sha256"
	"log"
	"math/big"
	"math/rand"
	"time"
)

func main() {
	//
	// Define the oracle
	//

	type Oracle struct {
		hashes   map[ [sha256.Size]byte ]bool
		privkeys map[string]rsa.PrivKey

		AddPrivKey func(string, *rsa.PrivKey)
		Decrypt    func(string, []byte) []byte
	}

	oracle := func() *Oracle {
		oracle := Oracle{
			  hashes: make(map[ [sha256.Size]byte ]bool),
			privkeys: make(map[string]rsa.PrivKey),
		}

		oracle.AddPrivKey = func(user string, privkey *rsa.PrivKey) {
			oracle.privkeys[user] = *privkey
		}

		oracle.Decrypt = func(user string, ciphertext []byte) []byte {
			privkey, ok := oracle.privkeys[user]
			if !ok {
				log.Panic("user privkey not found")
			}

			hash := sha256.Sum256(ciphertext)
			if _, ok := oracle.hashes[hash]; ok {
				log.Panic("multiple decrypt attempts detected")
			}
			oracle.hashes[hash] = true

			return privkey.Decrypt(ciphertext)
		}

		return &oracle
	}()

	//
	// Implement the attack
	//

	user := "alice"
	privkey, pubkey := rsa.KeyPair(256)
	plaintext := []byte("attack at dawn")
	ciphertext := pubkey.Encrypt(plaintext)

	oracle.AddPrivKey(user, privkey)
	if !bytes.Equal(oracle.Decrypt(user, ciphertext), plaintext) {
		log.Panic("decrypt failed")
	}

	S := func(n *big.Int) *big.Int {
		if big.NewInt(1).Cmp(n) != -1 {
			log.Panic("n <= 1")
		}

		src := rand.New(rand.NewSource(time.Now().UnixNano()))
		for {
			x := new(big.Int).Rand(src, n)
			if x.Cmp(big.NewInt(1)) == 1 {
				return x
			}
		}
	}(pubkey.N)

	Cprime := new(big.Int).Mod(new(big.Int).Mul(rsa.Modexp(S, pubkey.E, pubkey.N),
	                                            new(big.Int).SetBytes(ciphertext)),
	                           pubkey.N)
	Pprime := new(big.Int).SetBytes(oracle.Decrypt(user, Cprime.Bytes()))

	P := new(big.Int).Mod(new(big.Int).Mul(Pprime, rsa.Invmod(S, pubkey.N)), pubkey.N)
	if P.Cmp(new(big.Int).SetBytes(plaintext)) != 0 {
		log.Panic("attack failed")
	}

	log.Printf("decrypted message: %q", string(P.Bytes()))
}
