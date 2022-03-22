echo "Genomic files will be generated in tmpFiles directory and the test results will be saved in testResults directory.."
mkdir tmpFiles
mkdir testResults
cd ./test/exercise
echo "Let's generate some example genomic files for tests.."
go test fileGenerate_test.go -v -timeout 30m
echo "Now, let's run the main tests.."
echo "Test_0 starts.."
go test opTimeCheck_test.go -v
echo "Test_1, 2, 3, and 5 starts.."
cd ../mainTest
go run main.go -v -timeout 24h
echo "Test 4 starts.."
cd ../exercise
go test checkSigCost_test.go -v -timeout 24h
echo "Alright, all tests are finished! Now, I'll erase the genomic files in tmpFiles.."
go test fileErase_test.go -v
echo "Done! Thank you for your patience! :)"