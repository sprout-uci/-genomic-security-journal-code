package exercise

import (
	"log"
	"os"
	"testing"
)

func TestFileErase(test *testing.T) {

	err := os.RemoveAll("../../tmpFiles")
	if err != nil {
		log.Fatal(err)
	}

}
