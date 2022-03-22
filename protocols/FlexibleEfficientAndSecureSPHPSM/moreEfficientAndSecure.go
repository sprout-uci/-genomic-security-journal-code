package FlexibleEfficientAndSecureSPHPSM

/* This package implements Flexible, Efficient, & Secure SPH-PSM (FES-SPH-PSM) in Section 5.4 */

import (
	"bufio"
	"fmt"
	"math/big"
	"sync"
	"time"

	sl "github.com/eozturk1/genomic-security-journal-code/entities/sequencinglab"
	t "github.com/eozturk1/genomic-security-journal-code/entities/tester"
	env "github.com/eozturk1/genomic-security-journal-code/helpers/env"

	bp "github.com/ing-bank/zkrp/bulletproofs"
	"github.com/ing-bank/zkrp/ccs08"
	"github.com/ing-bank/zkrp/crypto/p256"
	"github.com/ing-bank/zkrp/util"
)

func Main(w *bufio.Writer, lab *sl.SequencingLab, tester *t.Tester, alice_genome, tester_genome []*env.Base, secParam uint32, withOpt bool, rangeProof int) bool {
	// rangeProof - 0: BulletProofs, 1: CCS08

	var wg sync.WaitGroup

	/* Offline Phase */
	timestart := time.Now()
	positions, aliceCiphers, salts, aliceSigs := lab.SequenceSNPSetRange(alice_genome)
	timecheck := time.Since(timestart)
	fmt.Println("SL offline phase is done")
	fmt.Fprintln(w, timecheck.Microseconds())

	timestart = time.Now()
	commitments := make([]*p256.P256, len(positions))
	wg.Add(len(positions))
	for i := uint32(0); i < uint32(len(positions)); i++ {
		go func(i uint32, wg *sync.WaitGroup) {
			commitments[i], _ = util.CommitG1(big.NewInt(int64(positions[i])), salts[i], lab.BPparams.H)
			wg.Done()
		}(i, &wg)
	}
	wg.Wait()
	timecheck = time.Since(timestart)
	fmt.Println("Alice offline phase is done")
	fmt.Fprintln(w, timecheck.Microseconds())

	timestart = time.Now()
	tester.Setup(lab, tester_genome, secParam)
	timecheck = time.Since(timestart)
	fmt.Println("Tester offline phase is done")
	fmt.Fprintln(w, timecheck.Microseconds())

	/* Online Phase */
	timestart = time.Now()
	startIndex, endIndex := env.ComputeBoundaryIndicesWRTRange(positions, tester.RangeStart, tester.RangeEnd)

	startIndexm1 := startIndex - 1
	if startIndexm1 < 0 {
		startIndexm1 = 0
	}
	endIndexp1 := endIndex + 1
	if endIndexp1 > uint32(len(aliceSigs)) {
		endIndexp1 = uint32(len(aliceSigs)) - 1
	}
	endIndexp2 := endIndex + 2
	if endIndexp2 > uint32(len(aliceCiphers)) {
		endIndexp2 = uint32(len(aliceCiphers)) - 1
	}

	slicedCipher := aliceCiphers[startIndexm1:endIndexp2]
	slicedComm := commitments[startIndexm1:endIndexp2]
	slicedSig := aliceSigs[startIndexm1:endIndexp1]

	if rangeProof == 0 { // bulletproof

		// generate lower bound proof
		params, _ := bp.SetupGeneric(0, int64(tester.RangeStart)) // to show the lower bound position < RangeStart
		l, _ := bp.ProveGeneric(big.NewInt(int64(positions[startIndexm1])), params)

		// generate upper bound proof
		params2, _ := bp.SetupGeneric(int64(tester.RangeEnd+1), int64(lab.GetMaxHumanGenomeSize()+10)) // to show the upper bound position >= RangeEnd + 1
		h, _ := bp.ProveGeneric(big.NewInt(int64(positions[endIndexp1])), params2)

		timecheck = time.Since(timestart)
		fmt.Println("Alice preprocessing in online phase is done")
		fmt.Fprintln(w, timecheck.Microseconds())

		timestart = time.Now()
		resultCipherArray := tester.TestingSNPRange(slicedComm, slicedCipher, slicedSig, &l, &h, withOpt)
		timecheck = time.Since(timestart)
		fmt.Println("Tester online phase is done")
		fmt.Fprintln(w, timecheck.Microseconds())

		timestart = time.Now()
		for i := 0; i < len(resultCipherArray); i++ {
			isZero := lab.Ahe.IsZero(resultCipherArray[i])
			if isZero {
				timecheck = time.Since(timestart)
				fmt.Println("Alice postprocessing in online phase is done")
				fmt.Fprintln(w, timecheck.Microseconds())
				return true
			}
		}
		timecheck = time.Since(timestart)
		fmt.Println("Alice postprocessing in online phase is done")
		fmt.Fprintln(w, timecheck.Microseconds())
		return false

	} else if rangeProof == 1 { // ccs08

		var lproof, hproof ccs08.CCS08Custom

		// generate lower bound proof
		lproof.Setup(0, int64(tester.RangeStart))
		lproof.Prove(big.NewInt(int64(positions[startIndexm1])))

		// generate upper bound proof
		hproof.Setup(int64(tester.RangeEnd+1), int64(lab.GetMaxHumanGenomeSize()+10))
		hproof.Prove(big.NewInt(int64(positions[endIndexp1])))

		timecheck = time.Since(timestart)
		fmt.Println("Alice preprocessing in online phase is done")
		fmt.Fprintln(w, timecheck.Microseconds())

		timestart = time.Now()
		resultCipherArray := tester.TestingSNPRangeCCS08(slicedComm, slicedCipher, slicedSig, &lproof, &hproof, withOpt)
		timecheck = time.Since(timestart)
		fmt.Println("Tester online phase is done")
		fmt.Fprintln(w, timecheck.Microseconds())

		timestart = time.Now()
		for i := 0; i < len(resultCipherArray); i++ {
			isZero := lab.Ahe.IsZero(resultCipherArray[i])
			if isZero {
				timecheck = time.Since(timestart)
				fmt.Println("Alice postprocessing in online phase is done")
				fmt.Fprintln(w, timecheck.Microseconds())
				return true
			}
		}
		timecheck = time.Since(timestart)
		fmt.Println("Alice postprocessing in online phase is done")
		fmt.Fprintln(w, timecheck.Microseconds())
		return false

	} else {

		fmt.Println("rp should be 0 (bulletproofs) or 1 (ccs08).")

	}

	return false

}
