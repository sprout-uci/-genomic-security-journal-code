package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"testing"
)

func TestExtra(test *testing.T) {

	//	runtime.GOMAXPROCS(1) // uncomment this for single-threading

	// Output results to the file "testExtra_result.txt"
	f, err := os.Create("../../testResults/testExtra_result.txt")
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

	/* Test_extra: comparing performance using ElGamal and Paillier in all protocols, where n=10^6, ratio n:m = 10:5 */
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

	w.Flush()
	return
}
