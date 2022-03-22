package exercise

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	sl "github.com/eozturk1/genomic-security-journal-code/entities/sequencinglab"
	ahe "github.com/eozturk1/genomic-security-journal-code/helpers/addhomencer"
	env "github.com/eozturk1/genomic-security-journal-code/helpers/env"

	//	t "github.com/eozturk1/genomic-security-journal-code/entities/tester"

	//	"github.com/ing-bank/zkrp/crypto/p256"
	"github.com/ing-bank/zkrp/bulletproofs"
	"github.com/ing-bank/zkrp/ccs08"
	"github.com/ing-bank/zkrp/util"
)

/**************************************
This file is to compute the time for each functions (operations).
To run this code, you can do "go test (filename).go -v"
**************************************/

func TestEtcOperationTimes(test *testing.T) {

	outputFileName := "../../testResults/EtcOps_times.txt"
	output, _ := os.Create(outputFileName)
	defer output.Close()
	w := bufio.NewWriter(output)

	scheme := ahe.AHElGamal{}
	scheme.Setup()

	lab := sl.SequencingLab{}
	lab.Setup(&scheme)

	signingKey := lab.GetSigningKey()

	base := env.Base{Position: uint32(1000000000), Letter: 'T'}
	base2 := env.Base{Position: uint32(2000000000), Letter: 'A'}

	var hash1List []int64 // H(position, base)
	var hash2List []int64 // H(position, cipher)
	var hash3List []int64 // H(tuple)
	var saltGenList []int64
	var sign1List []int64
	var sign2List []int64
	var verifySig1List []int64
	var verifySig2List []int64
	var commGenList []int64
	var RPGenList []int64
	var RPVerifyList []int64
	var ccs08RPGenList []int64
	var ccs08RPVerifyList []int64

	for i := 0; i < 10; i++ {

		timestart := time.Now()
		hash1Result := env.HashPositionAndBase(lab.Hash, base.Position, &base)
		timecheck := time.Since(timestart)
		//fmt.Fprintln(w, "H(position, base) time:")
		//fmt.Fprintln(w, timecheck.Microseconds())
		hash1List = append(hash1List, timecheck.Microseconds())

		ciphertext := scheme.Encrypt(new(big.Int).SetBytes(hash1Result))

		hash1Result = env.HashPositionAndBase(lab.Hash, base2.Position, &base2)
		ciphertext2 := scheme.Encrypt(new(big.Int).SetBytes(hash1Result))

		timestart = time.Now()
		hash2Result := env.HashPositionAndCipher(lab.Hash, base.Position, ciphertext)
		timecheck = time.Since(timestart)
		//fmt.Fprintln(w, "H(position, ciphertext) time:")
		//fmt.Fprintln(w, timecheck.Microseconds())
		hash2List = append(hash2List, timecheck.Microseconds())

		timestart = time.Now()
		r1, s1, err := ecdsa.Sign(rand.Reader, signingKey, hash2Result)
		timecheck = time.Since(timestart)
		//fmt.Fprintln(w, "signing the hash of (position, cipher) time:")
		//fmt.Fprintln(w, timecheck.Microseconds())
		sign1List = append(sign1List, timecheck.Microseconds())

		timestart = time.Now()
		verification1Result := ecdsa.Verify(lab.VerifyingKey, hash2Result, r1, s1)
		if !verification1Result {
			fmt.Println("verifying signature of H(pos,cipher) is failed")
		}
		timecheck = time.Since(timestart)
		//fmt.Fprintln(w, "verifying the signature of H(position, cipher) time:")
		//fmt.Fprintln(w, timecheck.Microseconds())
		verifySig1List = append(verifySig1List, timecheck.Microseconds())

		timestart = time.Now()
		salt, _ := rand.Int(rand.Reader, bulletproofs.ORDER)
		timecheck = time.Since(timestart)
		//fmt.Fprintln(w, "salt generation time:")
		//fmt.Fprintln(w, timecheck.Microseconds())
		saltGenList = append(saltGenList, timecheck.Microseconds())

		salt2, _ := rand.Int(rand.Reader, bulletproofs.ORDER)

		timestart = time.Now()
		commitment, err := util.CommitG1(big.NewInt(int64(base.Position)), salt, lab.BPparams.H)
		if err != nil {
			panic(err)
		}
		timecheck = time.Since(timestart)
		//fmt.Fprintln(w, "commitment generation time:")
		//fmt.Fprintln(w, timecheck.Microseconds())
		commGenList = append(commGenList, timecheck.Microseconds())

		commitment2, _ := util.CommitG1(big.NewInt(int64(base2.Position)), salt2, lab.BPparams.H)

		timestart = time.Now()
		hash3Result := env.HashTuple(lab.Hash, commitment, ciphertext, commitment2, ciphertext2)
		timecheck = time.Since(timestart)
		//fmt.Fprintln(w, "H(comm1, cipher1, comm2, cipher2) time:")
		//fmt.Fprintln(w, timecheck.Microseconds())
		hash3List = append(hash3List, timecheck.Microseconds())

		timestart = time.Now()
		r2, s2, err := ecdsa.Sign(rand.Reader, signingKey, hash3Result)
		timecheck = time.Since(timestart)
		//fmt.Fprintln(w, "signing the hash of tuple time:")
		//fmt.Fprintln(w, timecheck.Microseconds())
		sign2List = append(sign2List, timecheck.Microseconds())

		timestart = time.Now()
		verification2Result := ecdsa.Verify(lab.VerifyingKey, hash3Result, r2, s2)
		if !verification2Result {
			fmt.Println("verifying signature of H(tuple) is failed")
			break
		}
		timecheck = time.Since(timestart)
		//fmt.Fprintln(w, "verifying the signature of H(tuple) time:")
		//fmt.Fprintln(w, timecheck.Microseconds())
		verifySig2List = append(verifySig2List, timecheck.Microseconds())

		timestart = time.Now()
		params, _ := bulletproofs.SetupGeneric(0, int64(1500000000))
		proof, _ := bulletproofs.ProveGeneric(big.NewInt(int64(base.Position)), params)
		timecheck = time.Since(timestart)
		//fmt.Fprintln(w, "range proof generation time:")
		//fmt.Fprintln(w, timecheck.Microseconds())
		RPGenList = append(RPGenList, timecheck.Microseconds())

		timestart = time.Now()
		ok, _ := proof.Verify()
		if !ok {
			fmt.Println("range proof verification is failed")
			break
		}
		timecheck = time.Since(timestart)
		//fmt.Fprintln(w, "range proof verification time:")
		//fmt.Fprintln(w, timecheck.Microseconds())
		RPVerifyList = append(RPVerifyList, timecheck.Microseconds())

		var proof2 ccs08.CCS08Custom
		timestart = time.Now()
		proof2.Setup(0, int64(1500000000))
		proof2.Prove(big.NewInt(int64(base.Position)))
		timecheck = time.Since(timestart)
		ccs08RPGenList = append(ccs08RPGenList, timecheck.Microseconds())

		timestart = time.Now()
		ok2 := proof2.Verify()
		if !ok2 {
			fmt.Println("ccs08 range proof verification is failed")
			break
		}
		timecheck = time.Since(timestart)
		ccs08RPVerifyList = append(ccs08RPVerifyList, timecheck.Microseconds())

		fmt.Println("Etc operation check is done")

	}

	//calculate the avaerages
	sumhash1 := int64(0)
	sumhash2 := int64(0)
	sumhash3 := int64(0)
	sumsaltGen := int64(0)
	sumsign1 := int64(0)
	sumsign2 := int64(0)
	sumverifySig1 := int64(0)
	sumverifySig2 := int64(0)
	sumcommGen := int64(0)
	sumRPGen := int64(0)
	sumRPVerify := int64(0)
	sumCcs08RPGen := int64(0)
	sumCcs08RPVerify := int64(0)

	for i := 0; i < 10; i++ {
		fmt.Fprintln(w, hash1List[i], hash2List[i], hash3List[i], saltGenList[i], sign1List[i], sign2List[i], verifySig1List[i], verifySig2List[i], commGenList[i], RPGenList[i], RPVerifyList[i], ccs08RPGenList[i], ccs08RPVerifyList[i])

		sumhash1 += hash1List[i]
		sumhash2 += hash2List[i]
		sumhash3 += hash3List[i]
		sumsaltGen += saltGenList[i]
		sumsign1 += sign1List[i]
		sumsign2 += sign2List[i]
		sumverifySig1 += verifySig1List[i]
		sumverifySig2 += verifySig2List[i]
		sumcommGen += commGenList[i]
		sumRPGen += RPGenList[i]
		sumRPVerify += RPVerifyList[i]
		sumCcs08RPGen += ccs08RPGenList[i]
		sumCcs08RPVerify += ccs08RPVerifyList[i]

	}
	fmt.Fprintln(w, sumhash1, sumhash2, sumhash3, sumsaltGen, sumsign1, sumsign2, sumverifySig1, sumverifySig2, sumcommGen, sumRPGen, sumRPVerify, sumCcs08RPGen, sumCcs08RPVerify)
	fmt.Fprintln(w, "Average values of 10 executions: (H(pos, base) / H(pos, cipher) / H(tuple) / gen(salt) / sign(H(pos,cipher)) / sign(H(tuple)) / verify(sig1) / verify(sig2) / gen(commitment) / gen(range_proof) / verify(range_proof) / ccs08_gen(range_proof) / ccs08_verify(range_proof) ) ")
	fmt.Fprintln(w, float64(sumhash1)/10.0)
	fmt.Fprintln(w, float64(sumhash2)/10.0)
	fmt.Fprintln(w, float64(sumhash3)/10.0)
	fmt.Fprintln(w, float64(sumsaltGen)/10.0)
	fmt.Fprintln(w, float64(sumsign1)/10.0)
	fmt.Fprintln(w, float64(sumsign2)/10.0)
	fmt.Fprintln(w, float64(sumverifySig1)/10.0)
	fmt.Fprintln(w, float64(sumverifySig2)/10.0)
	fmt.Fprintln(w, float64(sumcommGen)/10.0)
	fmt.Fprintln(w, float64(sumRPGen)/10.0)
	fmt.Fprintln(w, float64(sumRPVerify)/10.0)
	fmt.Fprintln(w, float64(sumCcs08RPGen)/10.0)
	fmt.Fprintln(w, float64(sumCcs08RPVerify)/10.0)

	w.Flush()

}

func TestElGamalOperationTimes(test *testing.T) {

	outputFileName := "../../testResults/ElGamalOps_times.txt"
	output, _ := os.Create(outputFileName)
	defer output.Close()
	w := bufio.NewWriter(output)

	scheme := ahe.AHElGamal{}
	scheme.Setup()

	lab := sl.SequencingLab{}
	lab.Setup(&scheme)

	base := env.Base{Position: uint32(10), Letter: 'T'}
	hashBase := env.HashPositionAndBase(lab.Hash, base.Position, &base)

	var encList []int64
	var encInvList []int64
	var multCiphersList []int64
	var multConstantList []int64
	var isZeroList []int64

	for i := 0; i < 10; i++ {

		timestart := time.Now()
		cipher1 := scheme.Encrypt(new(big.Int).SetBytes(hashBase))
		timecheck := time.Since(timestart)
		//fmt.Fprintln(w, "ElGamal encryption time:")
		//fmt.Fprintln(w, timecheck.Microseconds())
		encList = append(encList, timecheck.Microseconds())

		timestart = time.Now()
		cipher2 := scheme.EncryptInverse(new(big.Int).SetBytes(hashBase))
		timecheck = time.Since(timestart)
		//fmt.Fprintln(w, "ElGamal encryption of inverse time:")
		//fmt.Fprintln(w, timecheck.Microseconds())
		encInvList = append(encInvList, timecheck.Microseconds())

		timestart = time.Now()
		multciphers := scheme.MultCiphers(cipher1, cipher2)
		timecheck = time.Since(timestart)
		//fmt.Fprintln(w, "ElGamal mult ciphers time:")
		//fmt.Fprintln(w, timecheck.Microseconds())
		multCiphersList = append(multCiphersList, timecheck.Microseconds())

		r, _ := rand.Int(rand.Reader, scheme.GetGroupOrder())
		timestart = time.Now()
		randomized := scheme.HideCipherWithR(multciphers, r)
		timecheck = time.Since(timestart)
		//fmt.Fprintln(w, "ElGamal randomization time:")
		//fmt.Fprintln(w, timecheck.Microseconds())
		multConstantList = append(multConstantList, timecheck.Microseconds())

		timestart = time.Now()
		isZero := scheme.IsZero(randomized)
		timecheck = time.Since(timestart)
		//fmt.Fprintln(w, "ElGamal isZero time:")
		//fmt.Fprintln(w, timecheck.Microseconds())
		isZeroList = append(isZeroList, timecheck.Microseconds())
		if isZero {
			fmt.Println("ElGamal time check is done")
		} else {
			fmt.Println("really? sth is wrong...")
		}
	}

	//calculate the avaerages
	sumEnc := int64(0)
	sumEncInv := int64(0)
	sumMultCiphers := int64(0)
	sumMultConstant := int64(0)
	sumIsZero := int64(0)

	for i := 0; i < 10; i++ {
		fmt.Fprintln(w, encList[i], encInvList[i], multCiphersList[i], multConstantList[i], isZeroList[i])

		sumEnc += encList[i]
		sumEncInv += encInvList[i]
		sumMultCiphers += multCiphersList[i]
		sumMultConstant += multConstantList[i]
		sumIsZero += isZeroList[i]
	}
	//fmt.Fprintln(w, sumEnc, sumEncInv, sumMultCiphers, sumMultConstant, sumIsZero)
	fmt.Fprintln(w, "Average values of 10 executions: (enc/encInv/multCiphers/multConstant/isZero) ")
	fmt.Fprintln(w, float64(sumEnc)/10.0)
	fmt.Fprintln(w, float64(sumEncInv)/10.0)
	fmt.Fprintln(w, float64(sumMultCiphers)/10.0)
	fmt.Fprintln(w, float64(sumMultConstant)/10.0)
	fmt.Fprintln(w, float64(sumIsZero)/10.0)

	w.Flush()

}

func TestPaillierOperationTimes(test *testing.T) {

	outputFileName := "../../testResults/PaillierOps_times.txt"
	output, _ := os.Create(outputFileName)
	defer output.Close()
	w := bufio.NewWriter(output)

	scheme := ahe.GoGoGadgetPaillier{}
	scheme.Setup()

	lab := sl.SequencingLab{}
	lab.Setup(&scheme)

	base := env.Base{Position: uint32(10), Letter: 'T'}
	hashBase := env.HashPositionAndBase(lab.Hash, base.Position, &base)

	var encList []int64
	var encInvList []int64
	var multCiphersList []int64
	var multConstantList []int64
	var isZeroList []int64

	for i := 0; i < 10; i++ {

		timestart := time.Now()
		cipher1 := scheme.Encrypt(new(big.Int).SetBytes(hashBase))
		timecheck := time.Since(timestart)
		//fmt.Fprintln(w, "Paillier encryption time:")
		//fmt.Fprintln(w, timecheck.Microseconds())
		encList = append(encList, timecheck.Microseconds())

		timestart = time.Now()
		cipher2 := scheme.EncryptInverse(new(big.Int).SetBytes(hashBase))
		timecheck = time.Since(timestart)
		//fmt.Fprintln(w, "Paillier encryption of inverse time:")
		//fmt.Fprintln(w, timecheck.Microseconds())
		encInvList = append(encInvList, timecheck.Microseconds())

		timestart = time.Now()
		multciphers := scheme.MultCiphers(cipher1, cipher2)
		timecheck = time.Since(timestart)
		//fmt.Fprintln(w, "Paillier mult ciphers time:")
		//fmt.Fprintln(w, timecheck.Microseconds())
		multCiphersList = append(multCiphersList, timecheck.Microseconds())

		r, _ := rand.Int(rand.Reader, scheme.GetGroupOrder())
		timestart = time.Now()
		randomized := scheme.HideCipherWithR(multciphers, r)
		timecheck = time.Since(timestart)
		//fmt.Fprintln(w, "Paillier randomization time:")
		//fmt.Fprintln(w, timecheck.Microseconds())
		multConstantList = append(multConstantList, timecheck.Microseconds())

		timestart = time.Now()
		isZero := scheme.IsZero(randomized)
		timecheck = time.Since(timestart)
		//fmt.Fprintln(w, "Paillier isZero time:")
		//fmt.Fprintln(w, timecheck.Microseconds())
		isZeroList = append(isZeroList, timecheck.Microseconds())
		if isZero {
			fmt.Println("Paillier time check is done")
		} else {
			fmt.Println("really? sth is wrong...")
		}
	}

	//calculate the avaerages
	sumEnc := int64(0)
	sumEncInv := int64(0)
	sumMultCiphers := int64(0)
	sumMultConstant := int64(0)
	sumIsZero := int64(0)

	for i := 0; i < 10; i++ {
		fmt.Fprintln(w, encList[i], encInvList[i], multCiphersList[i], multConstantList[i], isZeroList[i])

		sumEnc += encList[i]
		sumEncInv += encInvList[i]
		sumMultCiphers += multCiphersList[i]
		sumMultConstant += multConstantList[i]
		sumIsZero += isZeroList[i]
	}
	//fmt.Fprintln(w, sumEnc, sumEncInv, sumMultCiphers, sumMultConstant, sumIsZero)
	fmt.Fprintln(w, "Average values of 10 executions: (enc/encInv/multCiphers/multConstant/isZero) ")
	fmt.Fprintln(w, float64(sumEnc)/10.0)
	fmt.Fprintln(w, float64(sumEncInv)/10.0)
	fmt.Fprintln(w, float64(sumMultCiphers)/10.0)
	fmt.Fprintln(w, float64(sumMultConstant)/10.0)
	fmt.Fprintln(w, float64(sumIsZero)/10.0)

	w.Flush()

}
