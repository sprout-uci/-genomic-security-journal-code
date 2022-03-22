package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"testing"
)

func TestOne(test *testing.T) {

	// Output results to the file "test1_result.txt"
	f, err := os.Create("../../testResults/test1_result.txt")
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

	/* Test_1: Fix n (to 10^4, 10^5, and 10^6) and increase the ratio of n:m (from 10:1 to 10:10) */

	n = 10000
	s = 1000
	e = 1000
	param = 0 // with exact range

	for count := 0; count < 3; count += 1 { // n = 10^4, 10^5, 10^6
		diff := e
		for ; e <= n; e += diff { // ratio of n:m = 10:1, 10:2, 10:3, ..., 10:10

			fmt.Fprintln(w, "n: ", n, ", s: ", s, ", e: ", e)

			n_str := strconv.FormatUint(uint64(n), 10)
			s_str := strconv.FormatUint(uint64(s), 10)
			e_str := strconv.FormatUint(uint64(e), 10)

			fileA := "alice" + n_str + "from" + s_str + "to" + e_str
			fileTm := "testerFrom" + s_str + "to" + e_str

			callWholeElGamalTests(w, fileA, fileTm, param)
			callSNPElGamalTests(w, fileA, fileTm, param, withOpt, rp)
		}

		fmt.Fprintln(w, "Test1 - fixing n = 10^", 4+count, " and increasing ratio n:m - is finished!")
		n *= 10
		s *= 10
		e = diff * 10
	}
	fmt.Fprintln(w, "Test_1 - fixing n and increasing n:m - is finished!")

	w.Flush()
	return
}
