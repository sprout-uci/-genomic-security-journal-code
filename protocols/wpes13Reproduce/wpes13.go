package wpes13Reproduce

/* This package reproduced the Size- and Position-Hiding Private Substring Matching (SPHPSM) protocol in GoLang, suggested in WPES'13: https://dl.acm.org/doi/10.1145/2517840.2517849 */

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"math/big"
	"sync"
	"time"

	ahe "github.com/eozturk1/genomic-security-journal-code/helpers/addhomencer"
	env "github.com/eozturk1/genomic-security-journal-code/helpers/env"
)

func Main2013(w *bufio.Writer, lab *SequencingLab2013, tester *Tester2013, alice_genome, tester_genome []*env.Base) bool {

	/* Offline Phase */
	timestart := time.Now()
	aliceCiphers := AliceOfflineSetup(lab, alice_genome)
	timecheck := time.Since(timestart)
	fmt.Println("Alice offline phase is done")
	fmt.Fprintln(w, timecheck.Microseconds())

	timestart = time.Now()
	tester.OfflineSetup(lab, tester_genome)
	timecheck = time.Since(timestart)
	fmt.Println("Tester offline phase is done")
	fmt.Fprintln(w, timecheck.Microseconds())

	/* Online Phase */
	timestart = time.Now()
	encryptedResult := tester.Online(aliceCiphers)
	timecheck = time.Since(timestart)
	fmt.Println("Tester online phase is done")
	fmt.Fprintln(w, timecheck.Microseconds())

	timestart = time.Now()
	testingResult := lab.Ahe.IsZero(encryptedResult)
	timecheck = time.Since(timestart)
	fmt.Println("Alice online phase is done")
	fmt.Fprintln(w, timecheck.Microseconds())

	return testingResult

}

type SequencingLab2013 struct {
	Ahe  ahe.AddHomEncer
	Hash hash.Hash
}

type Tester2013 struct {
	EncryptedMarker  []*env.Cipher
	lab              *SequencingLab2013
	startingPosition uint32
}

func (lab *SequencingLab2013) Setup(scheme ahe.AddHomEncer) {
	lab.Ahe = scheme
	lab.Hash = sha256.New()
}

func AliceOfflineSetup(lab *SequencingLab2013, baseArray []*env.Base) []*env.Cipher {
	// Each bases are encrypted under an additively homomorphic encryption scheme
	var wg sync.WaitGroup

	numberOfBases := len(baseArray)
	encryptedGenome := make([]*env.Cipher, numberOfBases)

	wg.Add(numberOfBases)

	for i := uint32(0); i < uint32(numberOfBases); i++ {
		go func(i uint32, wg *sync.WaitGroup) {
			hashResult := env.HashPositionAndBase(lab.Hash, baseArray[i].Position, baseArray[i])
			encryptedGenome[i] = lab.Ahe.Encrypt(new(big.Int).SetBytes(hashResult))
			wg.Done()
		}(i, &wg)
	}
	wg.Wait()

	return encryptedGenome

}

func (t *Tester2013) OfflineSetup(lab *SequencingLab2013, baseArray []*env.Base) {
	// Each additive inverse of bases are encrypted under the same additively homomorphic encryption scheme
	var wg sync.WaitGroup

	t.lab = lab
	numberOfMarkers := len(baseArray)
	t.startingPosition = baseArray[0].Position
	encryptedMarker := make([]*env.Cipher, numberOfMarkers)

	wg.Add(numberOfMarkers)

	for i := uint32(0); i < uint32(numberOfMarkers); i++ {

		go func(i uint32, wg *sync.WaitGroup) {
			hashResult := env.HashPositionAndBase(lab.Hash, baseArray[i].Position, baseArray[i])
			encryptedMarker[i] = lab.Ahe.EncryptInverse(new(big.Int).SetBytes(hashResult))
			wg.Done()
		}(i, &wg)

	}
	wg.Wait()

	t.EncryptedMarker = encryptedMarker

}

func (t *Tester2013) Online(aliceCiphers []*env.Cipher) *env.Cipher {
	// For the marker's positions, Alice's encrypted bases are homomorphically added to Tester's encrypted bases and output the encrypted result after randomization
	// i.e., If matching, output Enc(0), or Enc(random number), otherwise.
	var wg sync.WaitGroup

	n := len(t.EncryptedMarker)
	result := t.lab.Ahe.Encrypt(big.NewInt(0))

	wg.Add(n)

	for i := uint32(0); i < uint32(n); i++ {

		go func(i uint32, wg *sync.WaitGroup) {
			j := t.startingPosition + i - 1
			mult := t.lab.Ahe.MultCiphers(aliceCiphers[j], t.EncryptedMarker[i])
			result = t.lab.Ahe.MultCiphers(result, mult)
			wg.Done()
		}(i, &wg)

	}
	wg.Wait()

	r, _ := rand.Int(rand.Reader, t.lab.Ahe.GetGroupOrder())
	result = t.lab.Ahe.HideCipherWithR(result, r)

	return result

}
