package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"

	"runtime"

	//	env "github.com/eozturk1/genomic-security-journal-code/env"
	sae "github.com/eozturk1/genomic-security-journal-code/protocols/EfficientAndSecureSPHPSM"
	fes "github.com/eozturk1/genomic-security-journal-code/protocols/FlexibleEfficientAndSecureSPHPSM"
	secure "github.com/eozturk1/genomic-security-journal-code/protocols/SecureSPHPSM"
	wpes13 "github.com/eozturk1/genomic-security-journal-code/protocols/wpes13Reproduce"
)

func main() {

	//	runtime.GOMAXPROCS(1) // uncomment this for single-threading

	// Output results to the file "testresult.txt"
	f, err := os.Create("../../testResults/testresult.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)

	var n, s, e, ns, ne, param uint32
	//var n, s, e, param uint32

	// set this 'true' for running the optimized code
	withOpt := true
	//withOpt := false

	// set this value for fixing range proof scheme:
	// 0: bulletproofs, 1: ccs08
	rp := 0

	/* Test_extra: comparing performance using ElGamal and Paillier in all protocols, where n=1-^6, ratio n:m = 10:5 */
	n = 1000000
	s = 100000
	e = 600000
	ns = s + 500
	ne = e + 500

	n_str := strconv.FormatUint(uint64(n), 10)
	s_str := strconv.FormatUint(uint64(s), 10)
	e_str := strconv.FormatUint(uint64(e), 10)
	ns_str := strconv.FormatUint(uint64(ns), 10)
	ne_str := strconv.FormatUint(uint64(ne), 10)

	fileA := "alice" + n_str + "from" + s_str + "to" + e_str
	fileTm := "testerFrom" + s_str + "to" + e_str
	fileTnm := "testerFrom" + ns_str + "to" + ne_str

	callMatchingTests(w, fileA, fileTm, fileTnm, param, withOpt, rp)
	fmt.Fprintln(w, "Test_extra - comparison of using ElGamal and Paillier - is done.")

	/* Test_0: comparing ElGamal and Paillier operations */
	// This test is located in separate test file (opTimeCheck_test.go). It can be done by "go test opTimeCheck_test.go -timeout 30m -v" in /test/exercise/ directory.
	fmt.Fprintln(w, "Test_0 - comparison of ElGamal and Paillier operations - needs to be done separately(, using opTimeCheck_test.go).")

	// now we test only for codes using ElGamal scheme
	/* Test_1: Fix n (to 10^4, 10^5, and 10^6) and increase the ratio of n:m (from 10:1 to 10:10) */

	n = 10000
	s = 1000
	e = 1000
	param = 0 // with exact range

	for count := 0; count < 3; count += 1 { // n = 10^4, 10^5, 10^6
		diff := e
		for ; e <= n; e += diff { // ratio of n:m = 10:1, 10:2, 10:3, ..., 10:10

			fmt.Fprintln(w, "n: ", n, ", s: ", s, ", e: ", e)

			n_str = strconv.FormatUint(uint64(n), 10)
			s_str = strconv.FormatUint(uint64(s), 10)
			e_str = strconv.FormatUint(uint64(e), 10)

			fileA = "alice" + n_str + "from" + s_str + "to" + e_str
			fileTm = "testerFrom" + s_str + "to" + e_str

			callWholeElGamalTests(w, fileA, fileTm, param)
			callSNPElGamalTests(w, fileA, fileTm, param, withOpt, rp)
		}

		fmt.Fprintln(w, "Test1 - fixing n = 10^", 4+count, " and increasing ratio n:m - is finished!")
		n *= 10
		s *= 10
		e = diff * 10
	}
	fmt.Fprintln(w, "Test_1 - fixing n and increasing n:m - is finished!")

	/* Test_2: Increase n (from 10^4 to 10^9) and fix the ratio of n:m (to 10:5) */
	// testings on whole genome are only until 10^6 due to bad performance (the rest are extrapolated)

	s = 1000
	e = 6000
	for n = 10000; n <= 1000000000; n *= 10 {

		fmt.Fprintln(w, "n: ", n, ", s: ", s, ", e: ", e)

		n_str = strconv.FormatUint(uint64(n), 10)
		s_str = strconv.FormatUint(uint64(s), 10)
		e_str = strconv.FormatUint(uint64(e), 10)

		fileA = "alice" + n_str + "from" + s_str + "to" + e_str
		fileTm = "testerFrom" + s_str + "to" + e_str

		if n <= 1000000 {
			callWholeElGamalTests(w, fileA, fileTm, param)
		}
		callSNPElGamalTests(w, fileA, fileTm, param, withOpt, rp)

		s *= 10
		e *= 10

	}
	fmt.Fprintln(w, "Test_2 - fixing ratio and increasing n - is finished!")

	/* Test_3: comparing optimized and non-optimized performance on ES-SPH-PSM and FES-SPH-PSM on singlethreading, n = 10^8, and ratio of n:m = 10:5 */

	n = 100000000
	s = 10000000
	e = 60000000
	runtime.GOMAXPROCS(1) // for singlethreading

	n_str = strconv.FormatUint(uint64(n), 10)
	s_str = strconv.FormatUint(uint64(s), 10)
	e_str = strconv.FormatUint(uint64(e), 10)

	fileA = "alice" + n_str + "from" + s_str + "to" + e_str
	fileTm = "testerFrom" + s_str + "to" + e_str

	// WITH optimization
	withOpt = true
	callSNPElGamalTests(w, fileA, fileTm, param, withOpt, rp)

	// WITHOUT optimization
	withOpt = false
	callSNPElGamalTests(w, fileA, fileTm, param, withOpt, rp)

	fmt.Fprintln(w, "Test_3 - evaluation for optimization - is finished!")

	/* Test_4: comparing performance of offline phases between wpes13Reproduce (SPH-PSM) and S-SPH-PSM to calculate the cost for signing the ciphertexts */
	// This test takes a lot of times, so we have it in separate test file (checkSigCost_test.go). It can be done by "go test checkSigCost_test.go -timeout 24h -v" in /test/exercise/ directory.
	fmt.Fprintln(w, "Test_4 - cost of adding signature to SPH-PSM - needs to be done separately(, using checkSigCost_test.go).")

	/* Test_5: run Test_2 with singlethreading */

	s = 1000
	e = 6000
	runtime.GOMAXPROCS(1) // for singlethreading
	for n = 10000; n <= 1000000000; n *= 10 {

		fmt.Fprintln(w, "n: ", n, ", s: ", s, ", e: ", e)

		n_str = strconv.FormatUint(uint64(n), 10)
		s_str = strconv.FormatUint(uint64(s), 10)
		e_str = strconv.FormatUint(uint64(e), 10)

		fileA = "alice" + n_str + "from" + s_str + "to" + e_str
		fileTm = "testerFrom" + s_str + "to" + e_str

		if n <= 1000000 {
			callWholeElGamalTests(w, fileA, fileTm, param)
		}
		callSNPElGamalTests(w, fileA, fileTm, param, withOpt, rp)

		s *= 10
		e *= 10

	}
	fmt.Fprintln(w, "Test_5 - Test_2 with singlethreading - is finished!")

	w.Flush()
	return

}

func callAll(w *bufio.Writer, fileA, fileTm, fileTnm string, param uint32, withOpt bool, rp int) {

	aliceWhole := fileA + ".txt"
	testerWholeM := fileTm + ".txt"
	testerWholeNM := fileTnm + ".txt"

	aliceSnp := fileA + "_snp.txt"
	testerSnpM := fileTm + "_snp.txt"
	testerSnpNM := fileTnm + "_snp.txt"

	wpes13.TestExactMatching(w, aliceWhole, testerWholeM)
	wpes13.TestNoMatching(w, aliceWhole, testerWholeNM)

	secure.TestElGamalExactMatching(w, aliceWhole, testerWholeM)
	secure.TestElGamalNoMatching(w, aliceWhole, testerWholeNM)
	secure.TestPaillierExactMatching(w, aliceWhole, testerWholeM)
	secure.TestPaillierNoMatching(w, aliceWhole, testerWholeNM)

	sae.TestElGamalExactMatching(w, aliceSnp, testerSnpM, withOpt)
	sae.TestElGamalNoMatching(w, aliceSnp, testerSnpNM, withOpt)
	sae.TestPaillierExactMatching(w, aliceSnp, testerSnpM, withOpt)
	sae.TestPaillierNoMatching(w, aliceSnp, testerSnpNM, withOpt)

	fes.TestElGamalExactMatching(w, aliceSnp, testerSnpM, param, withOpt, rp)
	fes.TestElGamalNoMatching(w, aliceSnp, testerSnpNM, param, withOpt, rp)
	fes.TestPaillierExactMatching(w, aliceSnp, testerSnpM, param, withOpt, rp)
	fes.TestPaillierNoMatching(w, aliceSnp, testerSnpNM, param, withOpt, rp)

}

func callMatchingTests(w *bufio.Writer, fileA, fileTm, fileTnm string, param uint32, withOpt bool, rp int) {

	aliceWhole := fileA + ".txt"
	testerWholeM := fileTm + ".txt"

	aliceSnp := fileA + "_snp.txt"
	testerSnpM := fileTm + "_snp.txt"

	wpes13.TestExactMatching(w, aliceWhole, testerWholeM)

	secure.TestElGamalExactMatching(w, aliceWhole, testerWholeM)
	secure.TestPaillierExactMatching(w, aliceWhole, testerWholeM)

	sae.TestElGamalExactMatching(w, aliceSnp, testerSnpM, withOpt)
	sae.TestPaillierExactMatching(w, aliceSnp, testerSnpM, withOpt)

	fes.TestElGamalExactMatching(w, aliceSnp, testerSnpM, param, withOpt, rp)
	fes.TestPaillierExactMatching(w, aliceSnp, testerSnpM, param, withOpt, rp)

}

func callWholeElGamalTests(w *bufio.Writer, fileA, fileTm string, param uint32) {

	aliceWhole := fileA + ".txt"
	testerWholeM := fileTm + ".txt"

	wpes13.TestExactMatching(w, aliceWhole, testerWholeM)

	secure.TestElGamalExactMatching(w, aliceWhole, testerWholeM)

}

func callSNPElGamalTests(w *bufio.Writer, fileA, fileTm string, param uint32, withOpt bool, rp int) {

	aliceSnp := fileA + "_snp.txt"
	testerSnpM := fileTm + "_snp.txt"

	sae.TestElGamalExactMatching(w, aliceSnp, testerSnpM, withOpt)

	fes.TestElGamalExactMatching(w, aliceSnp, testerSnpM, param, withOpt, rp)

}
