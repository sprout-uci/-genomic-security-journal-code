package addhomencer

import (
	"crypto/rand"
	//"fmt"
	"math/big"

	env "github.com/eozturk1/genomic-security-journal-code/helpers/env"
)

// ========================== Additively homomorphic ElGamal code, modified from golang.org/x/crypto/openpgp/elgamal ==========================
// This is the 1024-bit MODP group from RFC 5114, section 2.1:
const primeHex = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371"
const generatorHex = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5"

// This is the 2048-bit MODP group from RFC 5114, section 2.2:
const primeHex2 = "AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A317091883681286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F"
const generatorHex2 = "AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98AE247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA"

func fromHex(hex string) *big.Int {
	n, ok := new(big.Int).SetString(hex, 16)
	if !ok {
		panic("failed to parse hex number")
	}
	return n
}

type ElGamalPublicKey struct {
	G, P, Y *big.Int
}

type ElGamalPrivateKey struct {
	X *big.Int
}

type AHElGamal struct {
	Pk ElGamalPublicKey
	Sk ElGamalPrivateKey
}

func (ahelgamal *AHElGamal) Setup() {
	Pk := ElGamalPublicKey{
		G: fromHex(generatorHex2),
		P: fromHex(primeHex2),
	}

	Sk := ElGamalPrivateKey{
		X: fromHex("42"),
	}

	Pk.Y = new(big.Int).Exp(Pk.G, Sk.X, Pk.P)

	ahelgamal.Pk = Pk
	ahelgamal.Sk = Sk

	//fmt.Println("Setting up is done")
	//fmt.Println("private key: ", ahelgamal.Sk, "public key - G: ", ahelgamal.Pk.G, " P: ", ahelgamal.Pk.P, " Y: ", ahelgamal.Pk.Y)

}

func (ahelgamal *AHElGamal) Encrypt(b *big.Int) *env.Cipher {

	k, err := rand.Int(rand.Reader, ahelgamal.Pk.P)
	if err != nil {
		return nil
	}

	c1 := new(big.Int).Exp(ahelgamal.Pk.G, k, ahelgamal.Pk.P)
	s := new(big.Int).Exp(ahelgamal.Pk.Y, k, ahelgamal.Pk.P)
	ms := new(big.Int).Exp(ahelgamal.Pk.G, b, ahelgamal.Pk.P)
	c2 := s.Mul(s, ms)
	c2.Mod(c2, ahelgamal.Pk.P)

	//fmt.Println("Encryption of int ", b, " is done")

	return &env.Cipher{C1: c1, C2: c2}

}

func (ahelgamal *AHElGamal) IsZero(c *env.Cipher) bool {

	// if C1^x mod P == C2, that means G^m = 1, i.e., m = 0 mod P-1
	s := new(big.Int).Exp(c.C1, ahelgamal.Sk.X, ahelgamal.Pk.P)

	if s.Cmp(c.C2) == 0 {
		return true
	}

	return false

}

func (ahelgamal *AHElGamal) EncryptInverse(b *big.Int) *env.Cipher {

	k, err := rand.Int(rand.Reader, ahelgamal.Pk.P)
	if err != nil {
		return nil
	}

	c1 := new(big.Int).Exp(ahelgamal.Pk.G, k, ahelgamal.Pk.P)
	s := new(big.Int).Exp(ahelgamal.Pk.Y, k, ahelgamal.Pk.P)
	ms := new(big.Int).ModInverse(new(big.Int).Exp(ahelgamal.Pk.G, b, ahelgamal.Pk.P), ahelgamal.Pk.P) // (G^b)^(-1) = G^(-b) mod P
	c2 := s.Mul(s, ms)
	c2.Mod(c2, ahelgamal.Pk.P)

	return &env.Cipher{C1: c1, C2: c2}

}

func (ahelgamal *AHElGamal) InvertCipher(inputcipher *env.Cipher) *env.Cipher {

	c1 := new(big.Int).ModInverse(inputcipher.C1, ahelgamal.Pk.P)
	c2 := new(big.Int).ModInverse(inputcipher.C2, ahelgamal.Pk.P)
	return &env.Cipher{C1: c1, C2: c2}

}

func (ahelgamal *AHElGamal) MultCiphers(cipher1, cipher2 *env.Cipher) *env.Cipher {

	c1 := new(big.Int).Mod(new(big.Int).Mul(cipher1.C1, cipher2.C1), ahelgamal.Pk.P)
	c2 := new(big.Int).Mod(new(big.Int).Mul(cipher1.C2, cipher2.C2), ahelgamal.Pk.P)

	return &env.Cipher{C1: c1, C2: c2}

}

func (ahelgamal *AHElGamal) HideCipherWithR(cipher *env.Cipher, r *big.Int) *env.Cipher {

	c1 := new(big.Int).Exp(cipher.C1, r, ahelgamal.Pk.P)
	c2 := new(big.Int).Exp(cipher.C2, r, ahelgamal.Pk.P)

	return &env.Cipher{C1: c1, C2: c2}

}

func (ahelgamal *AHElGamal) GetGroupOrder() *big.Int {
	return ahelgamal.Pk.P
}

// ========================== Additively homomorphic ElGamal code, modified from golang.org/x/crypto/openpgp/elgamal ==========================
