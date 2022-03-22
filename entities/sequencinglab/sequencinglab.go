package sequencinglab

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	//	"fmt"
	"crypto/sha256"
	"hash"
	"io"
	"log"
	"math/big"
	"strings"
	"sync"

	"github.com/eozturk1/genomic-security-journal-code/helpers/addhomencer"
	"github.com/eozturk1/genomic-security-journal-code/helpers/env"
	"github.com/ing-bank/zkrp/bulletproofs"
	"github.com/ing-bank/zkrp/crypto/p256"
	"github.com/ing-bank/zkrp/util"
)

//var mutationsEveryNPosition = /* 1000 */ 1
//var genomeSizeInBases = /* 3000000000 */ 1000
const SaltSecretSizeInBytes = 16

var mAX_HUMAN_GENOME_SIZE = 3200000000

type SequencingLab struct {
	Ahe          addhomencer.AddHomEncer
	signingKey   *ecdsa.PrivateKey
	VerifyingKey *ecdsa.PublicKey
	Hash         hash.Hash
	BPparams     bulletproofs.BulletProofSetupParams
}

func (sl *SequencingLab) Setup(scheme addhomencer.AddHomEncer) {

	sl.Ahe = scheme

	p256 := elliptic.P256()
	var err error
	sl.signingKey, err = ecdsa.GenerateKey(p256, rand.Reader)
	if err != nil {
		panic("SL key generation error: " + err.Error())
	}
	sl.VerifyingKey = &sl.signingKey.PublicKey

	testString := strings.NewReader("Foo")
	sl.Hash = sha256.New()
	if _, err := io.Copy(sl.Hash, testString); err != nil {
		log.Fatal(err)
	}

	sl.BPparams, err = bulletproofs.Setup(bulletproofs.MAX_RANGE_END)
	if err != nil {
		panic(err)
	}
}

func (sl *SequencingLab) SequenceWholeSetRange(baseArray []*env.Base) ([]*env.Cipher, []*env.ECDSASignature) {
	// Encrypt each input bases and sign on Hash(position, ciphertext) for each ciphertext
	var wg sync.WaitGroup

	numberOfBases := len(baseArray)

	encryptedGenome := make([]*env.Cipher, numberOfBases)
	signatures := make([]*env.ECDSASignature, numberOfBases)

	wg.Add(numberOfBases)

	for i := uint32(0); i < uint32(numberOfBases); i++ {

		go func(i uint32, wg *sync.WaitGroup) {
			hashBase := env.HashPositionAndBase(sl.Hash, baseArray[i].Position, baseArray[i])
			encryptedGenome[i] = sl.Ahe.Encrypt(new(big.Int).SetBytes(hashBase))

			hashResult := env.HashPositionAndCipher(sl.Hash, baseArray[i].Position, encryptedGenome[i])

			r, s, serr := ecdsa.Sign(rand.Reader, sl.signingKey, hashResult)
			if serr != nil {
				panic(serr)
			}
			signatures[i] = &env.ECDSASignature{R: r, S: s}

			wg.Done()
		}(i, &wg)
	}

	wg.Wait()

	return encryptedGenome, signatures

}

func (sl *SequencingLab) SequenceSNPSetRange(baseArray []*env.Base) ([]uint32, []*env.Cipher, []*big.Int, []*env.ECDSASignature) {
	// Generate two additional bases for boundaries, encrypt each input base, generate commitments for each position values, and sign on the tuple (comm_i, cipher_i, comm_i+1, cipher_i+1)

	var wg sync.WaitGroup
	var err error

	numberOfBases := len(baseArray)

	positions := make([]uint32, numberOfBases+2)
	encryptedGenome := make([]*env.Cipher, numberOfBases+2)
	commitments := make([]*p256.P256, numberOfBases+2)
	signatures := make([]*env.ECDSASignature, numberOfBases+1)
	salts := make([]*big.Int, numberOfBases+2)

	wg.Add(numberOfBases + 2)
	// Generate random salts first
	for i := 0; i < numberOfBases+2; i++ {
		go func(i int, wg *sync.WaitGroup) {
			salts[i], _ = rand.Int(rand.Reader, bulletproofs.ORDER)
			wg.Done()
		}(i, &wg)
	}

	// Compute encrypted genome and commitments
	// Add m_0
	positions[0] = uint32(0)
	encryptedGenome[0] = sl.GetEncryptedBase(positions[0])
	wg.Wait()

	commitments[0], err = util.CommitG1(big.NewInt(int64(positions[0])), salts[0], sl.BPparams.H)
	if err != nil {
		panic(err)
	}

	wg.Add(numberOfBases + 1)
	for i := uint32(0); i <= uint32(numberOfBases); i++ { // from (0,1), (1,2) ..., (N, N+1)
		go func(i uint32, wg *sync.WaitGroup) {
			if i == uint32(numberOfBases) { // Add m_{n+1}
				positions[i+1] = uint32(mAX_HUMAN_GENOME_SIZE + 1) // any fixed number > N
				encryptedGenome[i+1] = sl.GetEncryptedBase(positions[i+1])
			} else {
				positions[i+1] = baseArray[i].Position
				hashBase := env.HashPositionAndBase(sl.Hash, baseArray[i].Position, baseArray[i])
				encryptedGenome[i+1] = sl.Ahe.Encrypt(new(big.Int).SetBytes(hashBase))
			}

			commitments[i+1], err = util.CommitG1(big.NewInt(int64(positions[i+1])), salts[i+1], sl.BPparams.H)
			if err != nil {
				panic(err)
			}
			wg.Done()
		}(i, &wg)
	}
	wg.Wait()

	// Compute hash of the tuple and sign it
	wg.Add(numberOfBases + 1)
	for i := uint32(0); i <= uint32(numberOfBases); i++ {
		go func(i uint32, wg *sync.WaitGroup) {
			hashResult := env.HashTuple(sl.Hash, commitments[i], encryptedGenome[i], commitments[i+1], encryptedGenome[i+1])

			r, s, serr := ecdsa.Sign(rand.Reader, sl.signingKey, hashResult)
			if serr != nil {
				panic(serr)
			}

			signatures[i] = &env.ECDSASignature{R: r, S: s}
			wg.Done()
		}(i, &wg)
	}
	wg.Wait()

	return positions, encryptedGenome, salts, signatures

}

func (sl *SequencingLab) GetEncryptedBase(position uint32) *env.Cipher {
	base := env.Base{Position: position, Letter: uint8('Z')} // additional base for boundaries
	hashBase := env.HashPositionAndBase(sl.Hash, base.Position, &base)
	return sl.Ahe.Encrypt(new(big.Int).SetBytes(hashBase))
}

func (sl *SequencingLab) SetMaxHumanGenomeSize(val int) {
	mAX_HUMAN_GENOME_SIZE = val
}

func (sl *SequencingLab) GetMaxHumanGenomeSize() int {
	return mAX_HUMAN_GENOME_SIZE
}

func (sl *SequencingLab) GetSigningKey() *ecdsa.PrivateKey {
	return sl.signingKey
}
