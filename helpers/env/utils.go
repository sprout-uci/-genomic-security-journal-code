package env

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"

	"github.com/ing-bank/zkrp/crypto/p256"
)

const delimeter = "del"

func (base *Base) ToBigInt() *big.Int {

	result := append(Uint32ToBytes(base.Position), base.Letter)
	//fmt.Println("Base to byte array: ", result)
	//fmt.Println("byte array to big.Int: ", new(big.Int).SetBytes(result))
	return new(big.Int).SetBytes(result)

}

func (base *Base) ToByteArray() []byte {
	result := append(Uint32ToBytes(base.Position), base.Letter)
	return result
}

//--- from https://gist.github.com/chiro-hiro/2674626cebbcb5a676355b7aaac4972d ---//
func Uint32ToBytes(val uint32) []byte {
	r := make([]byte, 4)
	for i := uint32(0); i < 4; i++ {
		r[i] = byte((val >> (8 * i)) & 0xff)
	}
	return r
}

func BytesToUint32(val []byte) uint32 {
	r := uint32(0)
	for i := uint32(0); i < 4; i++ {
		r |= uint32(val[i]) << (8 * i)
	}
	return r
}

//--- from https://gist.github.com/chiro-hiro/2674626cebbcb5a676355b7aaac4972d ---//

func HashPositionAndBase(h hash.Hash, position uint32, base *Base) []byte {
	// Output h(position || base)

	hashingValue := append(Uint32ToBytes(position), (base.ToBigInt()).Bytes()...)
	return h.Sum(hashingValue)

}

func HashPositionAndCipher(h hash.Hash, position uint32, cipher *Cipher) []byte {
	// Output h(position || cipher)

	hashingValue := append(Uint32ToBytes(position), cipher.C1.Bytes()...)
	if cipher.C2 != nil {
		hashingValue = append(hashingValue, cipher.C2.Bytes()...)
	}

	return h.Sum(hashingValue)

}

func HashTuple(h hash.Hash, com1 *p256.P256, cipher1 *Cipher, com2 *p256.P256, cipher2 *Cipher) []byte {
	//Output h(com1, cipher1, com2, cipher2)

	hashingValue := append(com1.X.Bytes(), com1.Y.Bytes()...)
	hashingValue = append(hashingValue, cipher1.C1.Bytes()...)
	if cipher1.C2 != nil {
		hashingValue = append(hashingValue, cipher1.C2.Bytes()...)
	}
	hashingValue = append(hashingValue, com2.X.Bytes()...)
	hashingValue = append(hashingValue, com2.Y.Bytes()...)
	hashingValue = append(hashingValue, cipher2.C1.Bytes()...)
	if cipher2.C2 != nil {
		hashingValue = append(hashingValue, cipher2.C2.Bytes()...)
	}

	return h.Sum(hashingValue)

}

func CompareP256s(curve1, curve2 *p256.P256) bool {
	// Compare two p256 inputs and return true when they are the same

	if curve1.X.Cmp(curve2.X) == 0 && curve1.Y.Cmp(curve2.Y) == 0 {
		return true
	}
	return false
}

func ComputeBoundaryIndicesWRTRange(positions []uint32, rangeStart, rangeEnd uint32) (uint32, uint32) {
	// Find starting and ending indices of positions with respect to the queried range

	var startingIndex, endingIndex uint32
	setStart, setEnd := false, false
	for i := uint32(0); i < uint32(len(positions)); i++ {
		if setStart && setEnd {
			break
		}
		if !setStart && positions[i] >= rangeStart {
			startingIndex = i
			setStart = true
		}
		if !setEnd && positions[i] > rangeEnd {
			endingIndex = i - 1
			setEnd = true
		}
	}

	return startingIndex, endingIndex
}

func GenerateGenomeInFile(fileName string, n, s, e uint32, isSNP bool) {
	// fileName : file name that generated genome will be written
	// n : #(Alice's whole genome) or 0 when generating tester's marker
	// s : starting position for 'T'
	// e : ending position for 'T'
	// i.e., Alice: 'T' in [s,e], 'A' in [1,s-1] and [e+1,n] and Tester: 'T' in [s,e]
	// isSNP : true/false if it is generating SNP or whole genome

	gap := uint32(1)
	if isSNP {
		gap = 1000
	}

	n = n / gap
	var base Base
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)

	if n != 0 {

		for i := uint32(0); i < n; i++ {
			position := (i + 1) * gap

			if position < s || position > e {
				base = Base{position, 'A'}
			} else {
				base = Base{position, 'T'}
			}
			err := enc.Encode(base)
			if err != nil {
				log.Fatal("encode: ", err)
			}
		}

	} else {

		m := e - s
		m = m / gap

		for i := uint32(0); ; i++ {
			position := (i + 1) * gap

			if position < s {
				continue
			} else if position > e {
				break
			} else {
				base = Base{position, 'T'}
				err := enc.Encode(base)
				if err != nil {
					log.Fatal("encode: ", err)
				}
			}
		}

	}

	fmt.Printf("Create a file, %s\n", fileName)
	file, err := os.Create(fileName)
	if err != nil {
		log.Fatal("Failed creating file")
	}

	defer file.Close()

	fmt.Println("Writing generated genome to the file..")
	len, err := file.Write(buffer.Bytes())
	if err != nil {
		log.Fatal("Failed writing to file")
	}

	_ = len
	fmt.Println("Done!")

	return

}

func ReadGenomeFromFile(fileName string) []*Base {

	path := "../../tmpFiles/"
	fileName = path + fileName

	fmt.Println("Reading file: ", fileName)
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Panicf("Failed reading data from file: %s", err)
	}

	var resultBases []*Base
	reader := bytes.NewReader(data)
	dec := gob.NewDecoder(reader)

	for i := 0; ; i++ {
		baseTmp := &Base{}
		err := dec.Decode(baseTmp)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatal("decode ", i, ": ", err)
		}
		resultBases = append(resultBases, baseTmp)
		//fmt.Println("baseTmp: ", baseTmp)
		//fmt.Println("resultBases[",i,"]: ", resultBases[i])
	}

	return resultBases

}
