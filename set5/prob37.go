package main

import (
	"./srp"

	"crypto/sha256"
	"log"
	"math/big"
)

func main() {
	i, p := "user@host", "secret"
	server := srp.NewServer(i, p)
	if !server.VerifyClient(srp.NewClient(i, p)) {
		log.Panic("srp verify failed")
	}

	//
	// Setting A = 0 forces S = 0 on the server
	//

	A := big.NewInt(0)
	S := big.NewInt(0)
	K := sha256.Sum256(S.Bytes())
	hmac := srp.HmacSha256(K[:], server.Salt)

	if !server.VerifyHmac(A, hmac[:]) {
		log.Panic("srp verify failed")
	}

	//
	// Setting A = N, N*2, ... also forces S = 0 on the server
	//

	for i := int64(1); i < 5; i++ {
		A := new(big.Int).Mul(srp.NistN, big.NewInt(i))

		S := big.NewInt(0)
		K := sha256.Sum256(S.Bytes())
		hmac := srp.HmacSha256(K[:], server.Salt)

		if !server.VerifyHmac(A, hmac[:]) {
			log.Panic("srp verify failed")
		}
	}
}
