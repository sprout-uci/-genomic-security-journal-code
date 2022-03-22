package FlexibleEfficientAndSecureSPHPSM

/* This package implements Flexible, Efficient, & Secure SPH-PSM (FES-SPH-PSM) in Section 5.4 */

import (
	"bufio"
	"fmt"
	"log"

	sl "github.com/eozturk1/genomic-security-journal-code/entities/sequencinglab"
	t "github.com/eozturk1/genomic-security-journal-code/entities/tester"
	ahe "github.com/eozturk1/genomic-security-journal-code/helpers/addhomencer"
	env "github.com/eozturk1/genomic-security-journal-code/helpers/env"
)

func TestElGamalExactMatching(w *bufio.Writer, fileA, fileTm string, secParam uint32, withOpt bool, rp int) {

	alice_genome := env.ReadGenomeFromFile(fileA)
	tester_genome := env.ReadGenomeFromFile(fileTm)

	scheme := ahe.AHElGamal{}
	scheme.Setup()

	lab := sl.SequencingLab{}
	lab.Setup(&scheme)

	tester := t.Tester{}

	fmt.Println("fes protocol, matching test with ElGamal starts!")
	result := Main(w, &lab, &tester, alice_genome, tester_genome, secParam, withOpt, rp)
	if !result {
		log.Fatal("Exact matching test: Failed\n")
	}
	fmt.Println("fes protocol, matching test with ElGamal finished!")
}

func TestElGamalNoMatching(w *bufio.Writer, fileA, fileTnm string, secParam uint32, withOpt bool, rp int) {

	alice_genome := env.ReadGenomeFromFile(fileA)
	tester_genome := env.ReadGenomeFromFile(fileTnm)

	scheme := ahe.AHElGamal{}
	scheme.Setup()

	lab := sl.SequencingLab{}
	lab.Setup(&scheme)

	tester := t.Tester{}

	fmt.Println("fes protocol, no matching test with ElGamal starts!")
	result := Main(w, &lab, &tester, alice_genome, tester_genome, secParam, withOpt, rp)
	if result {
		log.Fatal("No matching test: Failed\n")
	}
	fmt.Println("fes protocol, no matching test with ElGamal finished!")

}

//---------------

func TestPaillierExactMatching(w *bufio.Writer, fileA, fileTm string, secParam uint32, withOpt bool, rp int) {

	alice_genome := env.ReadGenomeFromFile(fileA)
	tester_genome := env.ReadGenomeFromFile(fileTm)

	scheme := ahe.GoGoGadgetPaillier{}
	scheme.Setup()

	lab := sl.SequencingLab{}
	lab.Setup(&scheme)

	tester := t.Tester{}

	fmt.Println("fes protocol, matching test with Paillier starts!")
	result := Main(w, &lab, &tester, alice_genome, tester_genome, secParam, withOpt, rp)
	if !result {
		log.Fatal("Exact matching test: Failed\n")
	}
	fmt.Println("fes protocol, matching test with Paillier finished!")

}

func TestPaillierNoMatching(w *bufio.Writer, fileA, fileTnm string, secParam uint32, withOpt bool, rp int) {

	alice_genome := env.ReadGenomeFromFile(fileA)
	tester_genome := env.ReadGenomeFromFile(fileTnm)

	scheme := ahe.GoGoGadgetPaillier{}
	scheme.Setup()

	lab := sl.SequencingLab{}
	lab.Setup(&scheme)

	tester := t.Tester{}

	fmt.Println("fes protocol, no matching test with Paillier starts!")
	result := Main(w, &lab, &tester, alice_genome, tester_genome, secParam, withOpt, rp)
	if result {
		log.Fatal("No matching test: Failed\n")
	}
	fmt.Println("fes protocol, no matching test with Paillier finished!")

}
