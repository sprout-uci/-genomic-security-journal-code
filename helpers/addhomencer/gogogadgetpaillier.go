package addhomencer

import (
	//	"fmt"
	"crypto/rand"
	"math/big"

	paillier "github.com/Roasbeef/go-go-gadget-paillier"
	env "github.com/eozturk1/genomic-security-journal-code/helpers/env"
)

// ========================== GoGoGadgetPaillier https://github.com/Roasbeef/go-go-gadget-paillier ===================
type GoGoGadgetPaillier struct {
	privateKey *paillier.PrivateKey
}

func (gggp *GoGoGadgetPaillier) Setup() {
	var err error
	gggp.privateKey, err = paillier.GenerateKey(rand.Reader, KeyLen)
	if err != nil {
		panic("GoGoGadgetPaillier GenerateKey error: " + err.Error())
	}
	//fmt.Println("GGGP set up is done, privateKey info: ", gggp.privateKey)
}

func (gggp *GoGoGadgetPaillier) Encrypt(b *big.Int) *env.Cipher {
	cipher, err := paillier.Encrypt(&gggp.privateKey.PublicKey, b.Bytes())
	if err != nil {
		panic("GoGoGadgetPaillier Encrypt error: " + err.Error())
	}
	cipherBigInt := new(big.Int).SetBytes(cipher)
	return &env.Cipher{C1: cipherBigInt}
}

func (gggp *GoGoGadgetPaillier) IsZero(c *env.Cipher) bool {
	plain, err := paillier.Decrypt(gggp.privateKey, c.C1.Bytes())
	if err != nil {
		panic("GoGoGadgetPaillier Decrypt error: " + err.Error())
	}
	plainBigInt := new(big.Int).SetBytes(plain)
	isZero := (big.NewInt(0).Cmp(plainBigInt) == 0)
	return isZero
}

func (gggp *GoGoGadgetPaillier) EncryptInverse(b *big.Int) *env.Cipher {

	// c = g^(-b) * r^n mod n^2
	g := gggp.privateKey.PublicKey.G
	n := gggp.privateKey.PublicKey.N
	n2 := gggp.privateKey.PublicKey.NSquared

	r, err := rand.Int(rand.Reader, n)
	if err != nil {
		return nil
	}

	gb_inv := new(big.Int).ModInverse(new(big.Int).Exp(g, b, n2), n2)
	c := new(big.Int).Mod(new(big.Int).Mul(gb_inv, new(big.Int).Exp(r, n, n2)), n2)

	return &env.Cipher{C1: c}

}

func (gggp *GoGoGadgetPaillier) InvertCipher(inputcipher *env.Cipher) *env.Cipher {

	c1 := new(big.Int).ModInverse(inputcipher.C1, gggp.privateKey.PublicKey.NSquared)
	return &env.Cipher{C1: c1}

}

func (gggp *GoGoGadgetPaillier) MultCiphers(cipher1, cipher2 *env.Cipher) *env.Cipher {

	cipher := paillier.AddCipher(&gggp.privateKey.PublicKey, cipher1.C1.Bytes(), cipher2.C1.Bytes())
	cipherBigInt := new(big.Int).SetBytes(cipher)
	return &env.Cipher{C1: cipherBigInt}

}

func (gggp *GoGoGadgetPaillier) HideCipherWithR(cipher *env.Cipher, r *big.Int) *env.Cipher {

	result := paillier.Mul(&gggp.privateKey.PublicKey, cipher.C1.Bytes(), r.Bytes())
	resultBigInt := new(big.Int).SetBytes(result)
	return &env.Cipher{C1: resultBigInt}

}

func (gggp *GoGoGadgetPaillier) GetGroupOrder() *big.Int {

	return gggp.privateKey.PublicKey.NSquared

}

// ========================== GoGoGadgetPaillier https://github.com/Roasbeef/go-go-gadget-paillier ===================
