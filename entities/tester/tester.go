package tester

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	mathRand "math/rand"
	"sync"
	"time"

	sl "github.com/eozturk1/genomic-security-journal-code/entities/sequencinglab"
	"github.com/eozturk1/genomic-security-journal-code/helpers/env"
	bp "github.com/ing-bank/zkrp/bulletproofs"
	"github.com/ing-bank/zkrp/ccs08"
	"github.com/ing-bank/zkrp/crypto/p256"
	"github.com/ing-bank/zkrp/util"
)

type Tester struct {
	EncryptedMarker  []*env.Cipher
	lab              *sl.SequencingLab
	startingPosition uint32
	endingPosition   uint32
	RangeStart       uint32
	RangeEnd         uint32
}

func (t *Tester) GetRangeQuery() (uint32, uint32) {

	return t.RangeStart, t.RangeEnd

}

func (t *Tester) Setup(lab *sl.SequencingLab, baseArray []*env.Base, secParam uint32) {

	var wg sync.WaitGroup

	t.lab = lab
	len := len(baseArray)
	t.startingPosition = baseArray[0].Position
	t.endingPosition = baseArray[len-1].Position
	//fmt.Println("tester starting position: ", t.startingPosition, ", ending position: ", t.endingPosition)

	// queried range = [s - p, e + p]
	tmpInt := int(t.startingPosition) - int(secParam)
	if tmpInt <= 0 {
		t.RangeStart = 1
	} else {
		t.RangeStart = uint32(tmpInt)
	}
	t.RangeEnd = t.endingPosition + secParam
	N := uint32(lab.GetMaxHumanGenomeSize())
	if t.RangeEnd > N {
		t.RangeEnd = N
	}
	//fmt.Println("tester range: ", t.RangeStart, t.RangeEnd)

	encryptedMarker := make([]*env.Cipher, len)

	//fmt.Println("Tester's marker: [")
	wg.Add(len)

	for i := uint32(0); i < uint32(len); i++ {

		go func(i uint32, wg *sync.WaitGroup) {
			hashBase := env.HashPositionAndBase(lab.Hash, baseArray[i].Position, baseArray[i])
			encryptedMarker[i] = lab.Ahe.EncryptInverse(new(big.Int).SetBytes(hashBase))

			//fmt.Printf("%v ", baseArray[i])
			wg.Done()
		}(i, &wg)

	}
	//fmt.Println("]\n")
	wg.Wait()

	t.EncryptedMarker = encryptedMarker

}

func (t *Tester) TestingWhole(ciphers []*env.Cipher, sigs []*env.ECDSASignature) *env.Cipher {

	var wg sync.WaitGroup

	wg.Add(len(t.EncryptedMarker))

	// Check if given ciphertexts are verified by signatures in marker's positions
	for i := t.startingPosition; i < t.startingPosition+uint32(len(t.EncryptedMarker)); i++ {

		go func(i uint32, wg *sync.WaitGroup) {
			hashResult := env.HashPositionAndCipher(t.lab.Hash, i, ciphers[i-1])

			verificationResult := ecdsa.Verify(t.lab.VerifyingKey, hashResult, sigs[i-1].R, sigs[i-1].S)
			if !verificationResult {
				fmt.Println("verification failed, so ABORT!")
				log.Fatal()
			}
			wg.Done()
		}(i, &wg)

	}
	wg.Wait()
	//fmt.Printf("All verifications from position %d to %d are PASSed!\n", t.startingPosition, t.startingPosition + uint32(len(t.EncryptedMarker)))

	wg.Add(len(t.EncryptedMarker))
	// Perform private testing
	//fmt.Println("Performing test..")
	result := t.lab.Ahe.Encrypt(big.NewInt(0))

	for i := uint32(0); i < uint32(len(t.EncryptedMarker)); i++ {

		go func(i uint32, wg *sync.WaitGroup) {
			j := t.startingPosition + i - 1
			mult := t.lab.Ahe.MultCiphers(ciphers[j], t.EncryptedMarker[i])
			result = t.lab.Ahe.MultCiphers(result, mult)
			wg.Done()
		}(i, &wg)
	}
	wg.Wait()

	r, _ := rand.Int(rand.Reader, t.lab.Ahe.GetGroupOrder())
	result = t.lab.Ahe.HideCipherWithR(result, r)

	//fmt.Println("Returning the result..")

	return result

}

func (t *Tester) TestingSNP(comm []*p256.P256, cipher []*env.Cipher, sig []*env.ECDSASignature, pos_init, pos_end, salt_init, salt_end *big.Int, withOpt bool) []*env.Cipher {

	var wg sync.WaitGroup

	// Check if all given commitments and ciphertexts are verified by signatures
	n := len(cipher) - 2
	N := t.lab.GetMaxHumanGenomeSize()

	if pos_init.Cmp(big.NewInt(0)) != 0 || pos_end.Cmp(big.NewInt(int64(N))) != 1 {
		fmt.Println("pos_init: ", pos_init, ", pos_end: ", pos_end)
		fmt.Println("Condition's not met, so ABORT!")
		return nil
	}
	//fmt.Println("Two boundary postions check passed!")

	com_init, _ := util.CommitG1(pos_init, salt_init, t.lab.BPparams.H)
	com_end, _ := util.CommitG1(pos_end, salt_end, t.lab.BPparams.H)
	if !env.CompareP256s(com_init, comm[0]) || !env.CompareP256s(com_end, comm[n+1]) {
		fmt.Println("commitments for boundaries are not matching, so ABORT!")
		return nil
	}
	//fmt.Println("Commitment checks for boundary positions passed!")

	wg.Add(n + 1)
	for i := uint32(0); i <= uint32(n); i++ {

		go func(i uint32, wg *sync.WaitGroup) {
			hashResult := env.HashTuple(t.lab.Hash, comm[i], cipher[i], comm[i+1], cipher[i+1])

			verificationResult := ecdsa.Verify(t.lab.VerifyingKey, hashResult, sig[i].R, sig[i].S)
			if !verificationResult {
				fmt.Println("verification failed, so ABORT!")
				log.Fatal()
			}
			wg.Done()
		}(i, &wg)

	}
	//fmt.Printf("All tuple verifications (from %d to %d) PASSed!\n", 0, n)
	wg.Wait()

	result := t.privateTestingForSNP(n, cipher, withOpt)
	return result

}

// zkrp:  bulletproof
func (t *Tester) TestingSNPRange(comm []*p256.P256, cipher []*env.Cipher, sig []*env.ECDSASignature, lproof *bp.ProofBPRP, hproof *bp.ProofBPRP, withOpt bool) []*env.Cipher {

	var wg sync.WaitGroup

	// Verify range proofs for boundaries
	ok_l, _ := lproof.Verify()
	ok_h, _ := hproof.Verify()
	if !(ok_l && ok_h) {
		fmt.Println("l: ", ok_l, ", h: ", ok_h)
		fmt.Println("Range proof result is invalid, so ABORT!")
		return nil
	}
	//fmt.Println("Range proofs are passed!\n")

	// Verify all the signatures
	n := len(cipher) - 2

	wg.Add(n + 1)

	for i := uint32(0); i <= uint32(n); i++ {

		go func(i uint32, wg *sync.WaitGroup) {
			hashResult := env.HashTuple(t.lab.Hash, comm[i], cipher[i], comm[i+1], cipher[i+1])

			verificationResult := ecdsa.Verify(t.lab.VerifyingKey, hashResult, sig[i].R, sig[i].S)
			if !verificationResult {
				fmt.Println("verification failed, so ABORT!")
				log.Fatal()
			}
			wg.Done()
		}(i, &wg)
	}
	//fmt.Println("All tuple verifications of input values PASSed!")
	wg.Wait()

	result := t.privateTestingForSNP(n, cipher, withOpt)
	return result

}

// zkrp: ccs08
func (t *Tester) TestingSNPRangeCCS08(comm []*p256.P256, cipher []*env.Cipher, sig []*env.ECDSASignature, lproof *ccs08.CCS08Custom, hproof *ccs08.CCS08Custom, withOpt bool) []*env.Cipher {

	var wg sync.WaitGroup

	// Verify range proofs for boundaries
	ok_l := lproof.Verify()
	ok_h := hproof.Verify()
	if !(ok_l && ok_h) {
		fmt.Println("l: ", ok_l, ", h: ", ok_h)
		fmt.Println("Range proof result is invalid, so ABORT!")
		return nil
	}
	//fmt.Println("Range proofs are passed!\n")

	// Verify all the signatures
	n := len(cipher) - 2

	wg.Add(n + 1)

	for i := uint32(0); i <= uint32(n); i++ {

		go func(i uint32, wg *sync.WaitGroup) {
			hashResult := env.HashTuple(t.lab.Hash, comm[i], cipher[i], comm[i+1], cipher[i+1])

			verificationResult := ecdsa.Verify(t.lab.VerifyingKey, hashResult, sig[i].R, sig[i].S)
			if !verificationResult {
				fmt.Println("verification failed, so ABORT!")
				log.Fatal()
			}
			wg.Done()
		}(i, &wg)
	}
	//fmt.Println("All tuple verifications of input values PASSed!")

	result := t.privateTestingForSNP(n, cipher, withOpt)
	return result

}

func (t *Tester) privateTestingForSNP(numOfCiphers int, inputCipher []*env.Cipher, withOpt bool) []*env.Cipher {

	var wg sync.WaitGroup

	numOfMarkers := len(t.EncryptedMarker)

	// random permutation for shuffling the order
	mathRand.Seed(time.Now().UnixNano())
	perm := mathRand.Perm(numOfCiphers)

	result := make([]*env.Cipher, numOfCiphers)

	// with no optimization
	if !withOpt {
		wg.Add(numOfCiphers - numOfMarkers + 1)
		for i := 0; i <= numOfCiphers-numOfMarkers; i++ {
			go func(i int, wg *sync.WaitGroup) {
				result[perm[i]] = t.lab.Ahe.Encrypt(big.NewInt(0))

				for j := 0; j <= numOfMarkers-1; j++ {

					k := i + j + 1
					mult := t.lab.Ahe.MultCiphers(inputCipher[k], t.EncryptedMarker[j])
					result[perm[i]] = t.lab.Ahe.MultCiphers(result[perm[i]], mult)

				}

				r, _ := rand.Int(rand.Reader, t.lab.Ahe.GetGroupOrder())
				result[perm[i]] = t.lab.Ahe.HideCipherWithR(result[perm[i]], r)
				wg.Done()
			}(i, &wg)

		}
		wg.Wait()
	} else { // with optimization
		// first round: compute (1) = E(a_1) E(a_2) ... E(a_m) E(-t_1) E(-t_2) ... E(-t_m)
		result[perm[0]] = t.lab.Ahe.Encrypt(big.NewInt(0))
		for j := 0; j <= numOfMarkers-1; j++ {
			k := j + 1
			mult := t.lab.Ahe.MultCiphers(inputCipher[k], t.EncryptedMarker[j])
			result[perm[0]] = t.lab.Ahe.MultCiphers(result[perm[0]], mult)
		}

		tmp := result[perm[0]]
		r, _ := rand.Int(rand.Reader, t.lab.Ahe.GetGroupOrder())
		result[perm[0]] = t.lab.Ahe.HideCipherWithR(result[perm[0]], r)
		//fmt.Println("i: 0, isZero?: ", t.lab.Ahe.IsZero(result[perm[0]]))

		// iterate this from second to n-m+1 round: (i+1) = (i) (E(a_i))^-1 E(a_m+i) (== E(a_i+1) E(a_i+2) ... E(a_i+m) E(-t_1) ... E(-t_m) )
		for i := 1; i <= numOfCiphers-numOfMarkers; i++ {
			result[perm[i]] = t.lab.Ahe.Encrypt(big.NewInt(0))
			tmp = t.lab.Ahe.MultCiphers(tmp, t.lab.Ahe.InvertCipher(inputCipher[i]))
			tmp = t.lab.Ahe.MultCiphers(tmp, inputCipher[i+numOfMarkers])
			result[perm[i]] = t.lab.Ahe.MultCiphers(result[perm[i]], tmp)
			r, _ := rand.Int(rand.Reader, t.lab.Ahe.GetGroupOrder())
			result[perm[i]] = t.lab.Ahe.HideCipherWithR(result[perm[i]], r)
			//fmt.Println("i: ", i, ", isZero?: ", t.lab.Ahe.IsZero(result[perm[i]]))
		}
	}

	// generate additional results, to hide the size of marker
	wg.Add(numOfMarkers - 1)
	for i := numOfCiphers - numOfMarkers + 1; i <= numOfCiphers-1; i++ {
		go func(i int, wg *sync.WaitGroup) {
			result[perm[i]] = t.lab.Ahe.Encrypt(big.NewInt(1))
			wg.Done()
		}(i, &wg)
	}
	wg.Wait()

	return result

}
