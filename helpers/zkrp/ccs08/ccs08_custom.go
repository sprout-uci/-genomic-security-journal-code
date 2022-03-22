package ccs08

import (
	"fmt"
	"math/big"
	"crypto/rand"

	"github.com/ing-bank/zkrp/crypto/bn256"

)

type CCS08Custom struct {
	proof ccs08
}

func (custom *CCS08Custom) Setup(a, b int64) {

	custom.proof.Setup(a, b)

}

func (custom *CCS08Custom) Prove(secret *big.Int) {

	custom.proof.x = secret
	custom.proof.r, _ = rand.Int(rand.Reader, bn256.Order)
	err := custom.proof.Prove()
	if err != nil {
		fmt.Printf("Error while proving ccs08 zkrp: %s\n", err.Error())
	}

}

func (custom *CCS08Custom) Verify() bool {

	result, err := custom.proof.Verify()
	if err != nil {
		fmt.Printf("Error while verifying ccs08 zkrp: %s\n", err.Error())
	}
	return result

}

