package main

import (
	"flag"
	"fmt"
	rf "github.com/C-X1an/relayfence/internal/relayfence"
	"os"
)

func main() {
	out := flag.String("out", ".state/benchmark", "fresh output directory")
	operations := flag.Int("operations", 100, "operations per group")
	repeats := flag.Int("repeats", 5, "repetitions per group")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected arguments")
		os.Exit(2)
	}
	if e := rf.RunBenchmark(*out, *operations, *repeats); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	fmt.Println("PASS: synthetic benchmark completed; inspect raw results before making claims")
}
