module github.com/eozturk1/genomic-security-journal-code

go 1.16

require (
	github.com/Roasbeef/go-go-gadget-paillier v0.0.0-20181009074315-14f1f86b6000 // indirect
	github.com/ing-bank/zkrp v0.0.0-20200519071134-97a3cddb5627 // indirect
)

replace github.com/eozturk1/genomic-security-journal-code/helpers/addhomencer => ./helpers/addhomencer

replace github.com/eozturk1/genomic-security-journal-code/helpers/env => ./helpers/env

replace github.com/eozturk1/genomic-security-journal-code/entities/sequencinglab => ./entities/sequencinglab

replace github.com/ing-bank/zkrp => ./helpers/zkrp
