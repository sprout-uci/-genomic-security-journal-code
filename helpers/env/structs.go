package env

import (
	"math/big"
)

type Base struct {
	Position uint32
	Letter   uint8
}

type ECDSASignature struct {
	R *big.Int
	S *big.Int
}

type Cipher struct {
	C1 *big.Int
	C2 *big.Int
}
