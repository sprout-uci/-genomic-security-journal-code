package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"testing"
)

func TestFive(test *testing.T) {

	runtime.GOMAXPROCS(1) // uncomment this for single-threading

	// Output results to the file "test5_result.txt"
	f, err := os.Create("../../testResults/test5_result.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)

	var n, s, e, param uint32

	// set this 'true' for running the optimized code
	withOpt := true
	//withOpt := false

	// set this value for fixing range proof scheme:
	// 0: bulletproofs, 1: ccs08
	rp := 0

	/* Test_5: run Test_2 with singlethreading */

	s = 1000
	e = 6000
	runtime.GOMAXPROCS(1) // for singlethreading
	for n = 10000; n <= 1000000000; n *= 10 {

		fmt.Fprintln(w, "n: ", n, ", s: ", s, ", e: ", e)

		n_str := strconv.FormatUint(uint64(n), 10)
		s_str := strconv.FormatUint(uint64(s), 10)
		e_str := strconv.FormatUint(uint64(e), 10)

		fileA := "alice" + n_str + "from" + s_str + "to" + e_str
		fileTm := "testerFrom" + s_str + "to" + e_str

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
