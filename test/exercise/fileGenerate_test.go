package exercise

import (
	"strconv"
	"testing"

	env "github.com/eozturk1/genomic-security-journal-code/helpers/env"
)

func TestFileGenerate(test *testing.T) {

	var n, s, e, ns, ne uint32
	//var n, s, e uint32

	/* Test_0 file */

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

	env.GenFiles(fileA, fileTm, fileTnm, n, s, e, ns, ne)

	/* Test_1 files */

	n = 10000
	s = 1000
	e = 1000

	for count := 0; count < 3; count += 1 { // n = 10^4, 10^5, 10^6
		diff := e
		for ; e <= n; e += diff { // ratio of n:m = 10:1, 10:2, 10:3, ..., 10:10

			n_str = strconv.FormatUint(uint64(n), 10)
			s_str = strconv.FormatUint(uint64(s), 10)
			e_str = strconv.FormatUint(uint64(e), 10)

			fileA = "alice" + n_str + "from" + s_str + "to" + e_str
			fileTm = "testerFrom" + s_str + "to" + e_str

			env.GenFiles(fileA, fileTm, "", n, s, e, 0, 0)
		}

		n *= 10
		s *= 10
		e = diff * 10
	}

	/* Test_2 files */
	// Files with n=10^4, 10^5, and 10^6 are already generated when generating Test_1 files, so only need to cover n=10^7, 10^8, and 10^9
	s = 1000000
	e = 6000000
	for n = 10000000; n <= 1000000000; n *= 10 {

		n_str = strconv.FormatUint(uint64(n), 10)
		s_str = strconv.FormatUint(uint64(s), 10)
		e_str = strconv.FormatUint(uint64(e), 10)

		fileA = "alice" + n_str + "from" + s_str + "to" + e_str
		fileTm = "testerFrom" + s_str + "to" + e_str

		env.GenFiles(fileA, fileTm, "", n, s, e, ns, ne)

		s *= 10
		e *= 10

	}

	// Files for the remaining tests are already generated above.
	return
}
