package EfficientAndSecureSPHPSM

/* This package implements Efficient & Secure SPH-PSM (ES-SPH-PSM) in Section 5.3 */

import (
	"bufio"
	"fmt"
	"math/big"
	"sync"
	"time"

	sl "github.com/eozturk1/genomic-security-journal-code/entities/sequencinglab"
	t "github.com/eozturk1/genomic-security-journal-code/entities/tester"
	env "github.com/eozturk1/genomic-security-journal-code/helpers/env"

	"github.com/ing-bank/zkrp/crypto/p256"
	"github.com/ing-bank/zkrp/util"
)

func Main(w *bufio.Writer, lab *sl.SequencingLab, tester *t.Tester, alice_genome, tester_genome []*env.Base, withOpt bool) bool {

	var wg sync.WaitGroup

	/* Offline Phase */
	timestart := time.Now()
	positions, aliceCiphers, salts, aliceSigs := lab.SequenceSNPSetRange(alice_genome)
	timecheck := time.Since(timestart)
	fmt.Println("SL offline phase is done")
	fmt.Fprintln(w, timecheck.Microseconds())

	timestart = time.Now()
	numberOfMutations := len(aliceSigs) - 1 // n
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
	tester.Setup(lab, tester_genome, 0)
	timecheck = time.Since(timestart)
	fmt.Println("Tester offline phase is done")
	fmt.Fprintln(w, timecheck.Microseconds())

	/* Online Phase */
	timestart = time.Now()
	resultCipherArray := tester.TestingSNP(commitments, aliceCiphers, aliceSigs,
		big.NewInt(int64(positions[0])), big.NewInt(int64(positions[numberOfMutations+1])),
		salts[0], salts[numberOfMutations+1], withOpt)
	timecheck = time.Since(timestart)
	fmt.Println("Tester online phase is done")
	fmt.Fprintln(w, timecheck.Microseconds())

	timestart = time.Now()
	for i := 0; i < len(resultCipherArray); i++ {
		isZero := lab.Ahe.IsZero(resultCipherArray[i])
		if isZero {
			timecheck = time.Since(timestart)
			fmt.Println("Alice online phase is done")
			fmt.Fprintln(w, timecheck.Microseconds())
			return true
		}
	}
	timecheck = time.Since(timestart)
	fmt.Println("Alice online phase is done")
	fmt.Fprintln(w, timecheck.Microseconds())
	return false

}
