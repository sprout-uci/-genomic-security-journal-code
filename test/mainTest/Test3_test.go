package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"testing"
)

func TestThree(test *testing.T) {

	// Output results to the file "test3_result.txt"
	f, err := os.Create("../../testResults/test3_result.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)

	var n, s, e, param uint32

	// set this value for fixing range proof scheme:
	// 0: bulletproofs, 1: ccs08
	rp := 0

	/* Test_3: comparing optimized and non-optimized performance on ES-SPH-PSM and FES-SPH-PSM on singlethreading, n = 10^8, and ratio of n:m = 10:5 */

	n = 100000000
	s = 10000000
	e = 60000000
	runtime.GOMAXPROCS(1) // for singlethreading

	n_str := strconv.FormatUint(uint64(n), 10)
	s_str := strconv.FormatUint(uint64(s), 10)
	e_str := strconv.FormatUint(uint64(e), 10)

	fileA := "alice" + n_str + "from" + s_str + "to" + e_str
	fileTm := "testerFrom" + s_str + "to" + e_str

	// WITH optimization
	withOpt := true
	callSNPElGamalTests(w, fileA, fileTm, param, withOpt, rp)

	// WITHOUT optimization
	withOpt = false
	callSNPElGamalTests(w, fileA, fileTm, param, withOpt, rp)

	fmt.Fprintln(w, "Test_3 - evaluation for optimization - is finished!")

	w.Flush()
	return
}
