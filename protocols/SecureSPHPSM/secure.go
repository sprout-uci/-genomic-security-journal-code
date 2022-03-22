package SecureSPHPSM

/* This package implements Secure SPH-PSM (S-SPH-PSM) in Section 5.2 */

import (
	"bufio"
	"fmt"
	"time"

	sl "github.com/eozturk1/genomic-security-journal-code/entities/sequencinglab"
	t "github.com/eozturk1/genomic-security-journal-code/entities/tester"
	"github.com/eozturk1/genomic-security-journal-code/helpers/env"
)

func Main(w *bufio.Writer, lab *sl.SequencingLab, tester *t.Tester, alice_genome, tester_genome []*env.Base) bool {

	/* Offline Phase */
	timestart := time.Now()
	aliceCiphers, aliceSigs := lab.SequenceWholeSetRange(alice_genome)
	timecheck := time.Since(timestart)
	fmt.Println("SL offline phase is done")
	fmt.Fprintln(w, timecheck.Microseconds())

	timestart = time.Now()
	tester.Setup(lab, tester_genome, 0)
	timecheck = time.Since(timestart)
	fmt.Println("Tester offline phase is done")
	fmt.Fprintln(w, timecheck.Microseconds())

	/* Online Phase */
	timestart = time.Now()
	resultCipher := tester.TestingWhole(aliceCiphers, aliceSigs)
	timecheck = time.Since(timestart)
	fmt.Println("Tester online phase is done")
	fmt.Fprintln(w, timecheck.Microseconds())

	timestart = time.Now()
	testingResult := lab.Ahe.IsZero(resultCipher)
	timecheck = time.Since(timestart)
	fmt.Println("Alice online phase is done")
	fmt.Fprintln(w, timecheck.Microseconds())

	return testingResult

}
