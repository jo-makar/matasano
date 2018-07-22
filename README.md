# matasano
Matasano (now NCC Group) crypto challenges' (https://cryptopals.com) solutions

Note that the git commits are signed to prove that these solutions are my own.

Briefly, these are a collection of exercises that demonstrate attacks on real-world cryptography.
The exercises are derived from weaknesses in real-world systems and modern cryptographic
constructions covering topics from symmetric ciphers such as AES (in a variety of modes), padding
schemes such as PKCS#7, random number generators, hashing algorithmns, asymmetric ciphers such as
DSA and RSA, a variety of famous attacks, and so on.

- Problem set 1
  - [x] Convert hex to base64 and back
  - [x] Fixed XOR
  - [x] Single-character XOR Cipher
  - [x] Detect single-character XOR
  - [x] Repeating-key XOR Cipher
  - [x] Break repeating-key XOR
  - [x] AES in ECB Mode
  - [x] Detecting ECB
- Problem set 2
  - [x] Implement PKCS#7 padding
  - [x] Implement CBC Mode
  - [x] Write an oracle function and use it to detect ECB
  - [x] Byte-at-a-time ECB decryption, Full control version
  - [x] ECB cut-and-paste
  - [x] Byte-at-a-time ECB decryption, Partial control version
  - [x] PKCS#7 padding validation
  - [x] CBC bit flipping
- Problem set 3
  - [x] The CBC padding oracle
  - [x] Implement CTR mode
  - [x] Break fixed-nonce CTR mode using substitions
  - [x] Break fixed-nonce CTR mode using stream cipher analysis
  - [x] Implement the MT19937 Mersenne Twister RNG
  - [x] "Crack" an MT19937 seed
  - [x] Clone an MT19937 RNG from its output
  - [x] Create the MT19937 stream cipher and break it
- Problem set 4
  - [x] Break "random access read/write" AES CTR
  - [ ] CTR bit flipping
  - [ ] Recover the key from CBC with IV=Key
  - [ ] Implement a SHA-1 keyed MAC
  - [ ] Break a SHA-1 keyed MAC using length extension
  - [ ] Break an MD4 keyed MAC using length extension
  - [ ] Implement HMAC-SHA1 and break it with an artificial timing leak
  - [ ] Break HMAC-SHA1 with a slightly less artificial timing leak
- Problem set 5
  - [ ] Implement Diffie-Hellman
  - [ ] Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
  - [ ] Implement DH with negotiated groups, and break with malicious "g" parameters
  - [ ] Implement Secure Remote Password
  - [ ] Break SRP with a zero key
  - [ ] Offline dictionary attack on simplified SRP
  - [ ] Implement RSA
  - [ ] Implement an E=3 RSA Broadcast attack
- Problem set 6
  - [ ] Implement Unpadded Message Recovery Oracle
  - [ ] Bleichenbacher's e=3 RSA Attack
  - [ ] DSA Key Recovery From Nonce
  - [ ] DSA Nonce Recovery From Repeated Nonce
  - [ ] DSA Parameter Tampering
  - [ ] Decrypt RSA From One-Bit Oracle
  - [ ] Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)
  - [ ] Bleichenbacher's PKCS 1.5 Padding Oracle (Complete)

# License
This work is released to the public domain.
