package main

import (
	"./aes"
	"./pkcs7"

	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"
)

func main() {
	//
	// Define the oracle functions
	//
	
	rand.Seed(time.Now().UnixNano())
	randBytes := func(n uint) []byte {
		b := make([]byte, n)
		rand.Read(b)
		return b
	}

	oracleKey := randBytes(aes.BlockSize)

	oracleEncrypt := func(email string) []byte {
		makeProfile := func(email string) string {
			escape := func(s string) string {
				t := strings.ReplaceAll(s, "&", "&amp;")
				return strings.ReplaceAll(t, "=", "%3D")
			}

			var b strings.Builder
			b.WriteString("email=" + escape(email))
			b.WriteString("&uid=10&role=user")
			return b.String()
		}

		plaintext := []byte(makeProfile(email))

		padded, err := pkcs7.Pad(plaintext, aes.BlockSize)
		if err != nil {
			log.Panic(err)
		}

		ciphertext, err := aes.EcbEncrypt(padded, oracleKey)
		if err != nil {
			log.Panic(err)
		}
		return ciphertext
	}

	oracleDecrypt := func(ciphertext []byte) map[string]string {
		// TODO Should return map[string]([]string)
		parseProfile := func(input string) map[string]string {
			// Golang does not support negative lookahead for performance,
			// ie cannot use regexp.MustCompile("&(?!amp;)").Split(input, -1)

			split := func(s, sep, nla string) []string {
				var tokens []string
				for i, v := range strings.Split(s, sep) {
					if i > 0 && strings.HasPrefix(v, nla) {
						tokens[len(tokens)-1] += sep + v
					} else {
						tokens = append(tokens, v)
					}
				}
				return tokens
			}

			unescape := func(s string) string {
				t := strings.ReplaceAll(s, "%3D", "=")
				return strings.ReplaceAll(t, "&amp;", "&")
			}

			rv := make(map[string]string)
			for _, p := range split(input, "&", "amp;") {
				t := strings.SplitN(p, "=", 2)
				if len(t) != 2 {
					log.Panic(fmt.Errorf("unable to parse %q", input))
				}
				rv[unescape(t[0])] = unescape(t[1])
			}
			return rv
		}

		padded, err := aes.EcbDecrypt(ciphertext, oracleKey)
		if err != nil {
			log.Panic(err)
		}

		plaintext, err := pkcs7.Unpad(padded, aes.BlockSize)
		if err != nil {
			log.Panic(err)
		}

		return parseProfile(string(plaintext))
	}

	//
	// Step 1, arrange for the first n input blocks to be:
	//     email=<user>+<tag>@<domain>&uid=10&role=
 	//

	// 0123456789abcdef0123456789abcdef0123456789abcdef
	// email=username+arbitrary_tag@domain&uid=10&role=
	step1Output := oracleEncrypt("username+arbitrary_tag@domain")

 	//
 	// Step 2, arrange for the second input block to be:
 	//     admin<valid-padding>
 	//

 	// 0123456789abcdef0123456789abcdef
 	// email=username1+admin<-padding->
 	step2Output := oracleEncrypt("username1+admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b")

 	//
 	// Selectively combine the preceding output blocks to produce:
 	//     email=<user>+<tag>@<domain>&uid=10&role=admin<valid-padding>
 	//

 	contrived := make([]byte, 3*16 + 16)
 	copy(contrived[0:3*16], step1Output[0:3*16])
 	copy(contrived[3*16:4*16], step2Output[16:2*16])

	log.Printf("%#v", oracleDecrypt(contrived))
}
