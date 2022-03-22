package main

// same as file "checkSigCost_test.go" in exercise directory
import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	sl "github.com/eozturk1/genomic-security-journal-code/entities/sequencinglab"
	ahe "github.com/eozturk1/genomic-security-journal-code/helpers/addhomencer"
	env "github.com/eozturk1/genomic-security-journal-code/helpers/env"
	wpes13 "github.com/eozturk1/genomic-security-journal-code/protocols/wpes13Reproduce"
)

func TestFour(test *testing.T) {

	// Output results to the file "test4_result.txt"
	f, _ := os.Create("../../testResults/test4_result.txt")
	defer f.Close()
	w := bufio.NewWriter(f)

	scheme := ahe.AHElGamal{}
	scheme.Setup()

	lab13 := wpes13.SequencingLab2013{}
	lab13.Setup(&scheme)

	labS := sl.SequencingLab{}
	labS.Setup(&scheme)

	for n := 10000; n <= 1000000; n *= 10 {

		wpes13TimeAverage := int64(0)
		secureTimeAverage := int64(0)

		for i := 0; i < 10; i++ {
			s := n / 10
			e := s + n/2

			fmt.Println("n, s, e: ", n, s, e)

			n_str := strconv.FormatUint(uint64(n), 10)
			s_str := strconv.FormatUint(uint64(s), 10)
			e_str := strconv.FormatUint(uint64(e), 10)

			fileName := "alice" + n_str + "from" + s_str + "to" + e_str + ".txt"
			alice_genome := env.ReadGenomeFromFile(fileName)

			timestart := time.Now()
			_ = wpes13.AliceOfflineSetup(&lab13, alice_genome)
			timecheck := time.Since(timestart)
			fmt.Println("WPES13 - Alice offline phase is done")
			//fmt.Fprintln(w, timecheck.Microseconds())
			wpes13TimeAverage += timecheck.Microseconds()

			timestart = time.Now()
			_, _ = labS.SequenceWholeSetRange(alice_genome)
			timecheck = time.Since(timestart)
			fmt.Println("Secure - SL offline phase is done")
			//fmt.Fprintln(w, timecheck.Microseconds())
			secureTimeAverage += timecheck.Microseconds()
		}
		wpes13TimeAverage = wpes13TimeAverage / 10
		secureTimeAverage = secureTimeAverage / 10
		fmt.Fprintln(w, wpes13TimeAverage)
		fmt.Fprintln(w, secureTimeAverage)

	}

	w.Flush()
	return
}
