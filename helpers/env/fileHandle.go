package env

import (
	"os"
)

func GenFiles(fileA, fileTm, fileTnm string, n, s, e, ns, ne uint32) {

	path := "../../tmpFiles/"
	os.Mkdir("../../tmpFiles", 0755)

	GenerateGenomeInFile(path+fileA+".txt", n, s, e, false)
	GenerateGenomeInFile(path+fileTm+".txt", 0, s, e, false)
	if fileTnm != "" {
		GenerateGenomeInFile(path+fileTnm+".txt", 0, ns, ne, false)
	}

	GenerateGenomeInFile(path+fileA+"_snp.txt", n, s, e, true)
	GenerateGenomeInFile(path+fileTm+"_snp.txt", 0, s, e, true)
	if fileTnm != "" {
		GenerateGenomeInFile(path+fileTnm+"_snp.txt", 0, ns, ne, true)
	}

}

func EraseFiles(fileA, fileTm, fileTnm string) {

	path := "../../tmpFiles/"

	os.Remove(path + fileA + ".txt")
	os.Remove(path + fileTm + ".txt")
	if fileTnm != "" {
		os.Remove(path + fileTnm + ".txt")
	}

	os.Remove(path + fileA + "_snp.txt")
	os.Remove(path + fileTm + "_snp.txt")
	if fileTnm != "" {
		os.Remove(path + fileTnm + "_snp.txt")
	}

}
