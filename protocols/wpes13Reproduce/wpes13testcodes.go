package wpes13Reproduce

/* This package reproduced the Size- and Position-Hiding Private Substring Matching (SPHPSM) protocol in GoLang, suggested in WPES'13: https://dl.acm.org/doi/10.1145/2517840.2517849 */

import (
	"bufio"
	"fmt"
	"log"

	ahe "github.com/eozturk1/genomic-security-journal-code/helpers/addhomencer"
	env "github.com/eozturk1/genomic-security-journal-code/helpers/env"
)

func TestExactMatching(w *bufio.Writer, fileA, fileTm string) {

	alice_genome := env.ReadGenomeFromFile(fileA)
	tester_genome := env.ReadGenomeFromFile(fileTm)

	scheme := ahe.AHElGamal{}
	scheme.Setup()

	lab := SequencingLab2013{}
	lab.Setup(&scheme)

	tester := Tester2013{}

	fmt.Println("wpes13 reproduced protocol, matching test starts!")
	result := Main2013(w, &lab, &tester, alice_genome, tester_genome)
	if !result {
		log.Fatal("Exact matching test: Failed\n")
	}
	fmt.Println("wpes13 reproduced protocol, matching test finished!")

	return
}

func TestNoMatching(w *bufio.Writer, fileA, fileTnm string) {

	alice_genome := env.ReadGenomeFromFile(fileA)
	tester_genome := env.ReadGenomeFromFile(fileTnm)

	scheme := ahe.AHElGamal{}
	scheme.Setup()

	lab := SequencingLab2013{}
	lab.Setup(&scheme)

	tester := Tester2013{}

	fmt.Println("wpes13 reproduced protocol, no matching test starts!")
	result := Main2013(w, &lab, &tester, alice_genome, tester_genome)
	if result {
		log.Fatal("No matching test: Failed\n")
	}
	fmt.Println("wpes13 reproduced protocol, no matching test finished!")

	return
}
