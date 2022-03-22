# Implementation and Evaluation Code for Balancing Security and Privacy in Genomic Range Queries

Fascinating recent advances in genome sequencing, coupled with greatly reduced storage and computation costs, make genomic
testing increasingly accessible to individuals. Today, one can easily obtain their digitized DNA from a sequencing lab and later use it to
conduct numerous tests by engaging with a testing facility. Due to the inherent sensitivity of genetic material and the often-proprietary
nature of genomic tests, privacy is a natural and crucial issue. While genomic privacy received immense attention within and outside
the research community, genomic security is not sufficiently studied. This is surprising since the usage of fake or altered genomes can
have grave consequences, such as wrong drug prescriptions and genetic test outcomes.

Unfortunately, in the genomic domain, privacy and security are (as often happens) at odds with each other. In this paper, we attempt
to reconcile security with privacy in genomic testing by designing a novel technique for a secure and private genomic range query
protocol between a genomic testing facility and an individual user. The proposed technique maintains authenticity and completeness of
user-supplied genomic material while maintaining its privacy by releasing only the minimum thereof. To emphasize its broad aptitude
for various problems, we show how to apply the proposed technique to a previous genomic private substring matching protocol.
Experiments show that our technique offers fairly good performance and it thus is quite practical. Furthermore, we generalize the
genomic range query problem to sparse integer sets and discuss potential use cases.

For more details, please check our paper available at: (TBD)
Note that this repository only includes the extended implementation described in Section 5. 
For implementation for Section 4, please refer to https://gitlab.com/eozturk1/range-proofs. // TODO: make it public

## Directory Structure
```
genomic-security-journal-code
├── entities
│   ├── sequencinglab
│   └── tester
├── helpers
│   ├── addhomencer                         // Additively homomorphic encryption schemes (ElGamal variant and Paillier)
│   ├── env                                 // other helper functions and structs defined
│   └── zkrp                                // code from https://github.com/ing-bank/zkrp
├── protocols
│   ├── wpes13Reproduce                     // reproduced code for [DFT'13]
│   ├── SecureSPHPSM                        // code for Section 5.2
│   ├── EfficientAndSecureSPHPSM            // code for Section 5.3
│   └── FlexibleEfficientAndSecureSPHPSM    // code for Section 5.4
├── test
│   ├── exercise
│   └── mainTest
├── testResultsForEval
├── testAll.sh
└── graph.ipynb
```
[[DFT'13]](https://dl.acm.org/doi/10.1145/2517840.2517849) E. De Cristofaro, S. Faber, and G. Tsudik. Secure genomic testing with size-and position-hiding private substring matching. In Proceedings of the 12th ACM workshop on Workshop on privacy in the electronic society, pages 107–118. ACM, 2013

## Dependencies

Our implementation uses Go and is tested on Ubuntu 20.04.2 LTS. To install Go, please refer to https://go.dev/doc/tutorial/getting-started#install.

## Evaluation Results

To run the entire tests on your machine, you can use our shell script `testAll.sh` or run tests in `test` directory.
This script will 1. generate example genomic files in `tmpFiles`, 2. run the whole tests and save the test results in `testResults`, and 3. erase all files in `tmpFiles`.
Note that running the whole tests takes time (probably more than 1 day).
We provide our evaluation results in `testResultsForEval` and graphs in `graphs.ipynb`. 

### Using the Script Given

To run the script file, clone this repository first, and then run the `testAll.sh` file as below.
```
./testAll.sh
```

### Testing Individually

To run each test separately, first follow the steps below and run individual tests.

1. Make directory for sample genomic data
```
mkdir tmpFiles
```

2. Make directory for test results
```
mkdir testResults
```

3. Generate sample genomic data
```
cd test/exercise
go test fileGenerate_test.go -v -timeout 30m 
```
Note. If it outputs timeout errors and quits, adjust the timeout values ,e.g. Use `1h` instead of `30m` above (Default value is 10m).

4. Run the tests as follows: (approximated times taken on our machine is commented for reference)

**Test_0: ElGamal vs Paillier**

Test_0 compares each operation cost of two additive homomorphic encryption schemes, ElGamal and Paillier.
In the extra test file, `Test_extra_test.go`, it compares the performance of all four protocols when using each ElGamal or Pailler, with n=10^6 and ratio n:m = 10:5.
*FYI: Test_0 took less than 10 minutes and Test_extra took less than 1 hour on our machine.*
```
cd test/mainTest
go test Test0_test.go main.go -v -timeout 30m 
go test Test_extra_test.go main.go -v -timeout 2h 
```

**Test_1: Fix n:=num(wholeGenes) and Increase m:=num(markers)**

This test shows the computation result of each protocol with fixing n (for each 10^4, 10^5, and 10^6) and increasing m (from 10:1 to 10:10).
*FYI: Test_1 took less than 6 hours on our machine.*
```
cd test/mainTest
go test Test1_test.go main.go -v -timeout 12h
```

**Test_2: Fix n:m ratio and Increase n from to 10^4 to 10^9**

This tests shows the computation results of each protocol with fixed n:m ratio (as 2:1) and increasing n.
*FYI: Test_2 took less than 7 hours on our machine.*
```
cd test/mainTest
go test Test2_test.go main.go -v -timeout 14h
```

**Test_3: (ES-SPH-PSM, FES-SPH-PSM only) optimized vs non-optimized performance**

This test compares the computation cost with/without optimization in ES-SPH-PSM and FES-SPH-PSM. The test is on singlethreading, n=10^8, and ratio n:m = 10:5.
*FYI: Test_3 took less than 28 hours on our machine.*
```
cd test/mainTest
go test Test3_test.go main.go -v -timeout 56h
```

**Test_4: Cost for Adding Security to SPH-PSM**

This is comparing Alice's computation cost in SPH-PSM offline phase and SL's computation cost in S-SPH-PSM offline phase. The gap between two costs means the cost for signing the ciphertexts.
*FYI: Test_4 took less than 4 hours on our machine.*
```
cd test/mainTest
go test Test4_test.go main.go -v -timeout 8h
```

**Test_5: Run Test_2 with Singlethreading**

This tests shows the computation results of the Test_2 with single-threading, i.e., with simglethreading and optimization (for ES-SPH-PSM and FES-SPH-PSM)
*FYI: Test_5 took less than 48 hours on our machine.*
```
cd test/mainTest
go test Test5_test.go main.go -v -timeout 96h
```