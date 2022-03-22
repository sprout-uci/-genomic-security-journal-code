package addhomencer

import (
	"math/big"

	env "github.com/eozturk1/genomic-security-journal-code/helpers/env"
)

const PrimeBitLen = 512

//const KeyLen = 1024
const KeyLen = 2048
const ConcurrencyLevel = 4

// Main AH Encryption interface.
// For each encryption method, fill out these methods.
type AddHomEncer interface {
	// Generate a key and set up anything else necessary for the encryption method.
	// Update the struct (See struct DidierCrunchPaillier) with variables as necessary.
	Setup()

	// Main encryption function. Cipher has c1 and c2 (to support AH-ElGamal), will be used as needed.
	Encrypt(b *big.Int) *env.Cipher

	// We don't necessarily decrypt -- as is the case for AH El-Gamal. Therefore we will implement this function to determine whether the result
	// is an encryption of zero.
	IsZero(c *env.Cipher) bool

	// Encrypt the additive inverse of input message, i.e., EncryptInverse(m) = E(-m)
	EncryptInverse(b *big.Int) *env.Cipher

	// MultCiphers multiplies two input ciphertexts, i.e., homomorphically adds two plaintexts of two input ciphertexts
	// i.e., cipher1 * cipher2 =  E(m1 + m2), where cipher1 = E(m1) and cipher2  = E(m2)
	MultCiphers(cipher1, cipher2 *env.Cipher) *env.Cipher

	// HideCipherWithR exponentiate the input ciphertext to the input constant, so that the original plaintext is hidden
	// i.e., cipher ^ r = E(m * r), where cipher = E(m)
	HideCipherWithR(cipher *env.Cipher, r *big.Int) *env.Cipher

	// Output the group order
	GetGroupOrder() *big.Int

	// Compute the inverse of an input ciphertext
	InvertCipher(inputcipher *env.Cipher) *env.Cipher
}
