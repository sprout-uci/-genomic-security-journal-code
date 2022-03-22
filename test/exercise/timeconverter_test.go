package exercise

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"testing"
	"time"
)

func TestTimeConvert(test *testing.T) {

	fileName := "times.txt"
	outputFileName := "time_converted.txt"

	fmt.Println("Opening the file")
	file, err := os.Open(fileName)
	if err != nil {
		test.Error("file opening error")
	}
	defer file.Close()

	fmt.Println("Creating the output file")
	output, _ := os.Create(outputFileName)
	defer output.Close()
	w := bufio.NewWriter(output)

	reader := bufio.NewReader(file)
	var line string
	for {
		line, err = reader.ReadString('\n')
		if err != nil && err != io.EOF {
			break
		}

		length := len(line)
		if length == 0 {
			break
		}
		newline := line[:length-1]
		
		dur, _ := time.ParseDuration(newline)
		fmt.Printf("Convert the time: %s to duration: %v\n", newline, dur)
		fmt.Printf("To microseconds: %.0f\n", float64(dur.Microseconds()))
		fmt.Fprintln(w, float64(dur.Microseconds()))

		if err != nil {
			break
		}
	}

	if err != io.EOF {
		test.Errorf("> Failed with err: %v\n", err)
	}
	
	w.Flush()

}
