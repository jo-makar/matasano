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
  - [ ] The CBC padding oracle
  - [ ] Implement CTR mode
  - [ ] Break fixed-nonce CTR mode using substitions
  - [ ] Break fixed-nonce CTR mode using stream cipher analysis
  - [ ] Implement the MT19937 Mersenne Twister RNG
  - [ ] "Crack" an MT19937 seed
  - [ ] Clone an MT19937 RNG from its output
  - [ ] Create the MT19937 stream cipher and break it

# License
This work is released to the public domain.
