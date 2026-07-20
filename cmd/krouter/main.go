package main

import (
	"fmt"
	"os"
)

func main() {
	mode := os.Getenv("KROUTER_MODE")

	switch mode {
	case "controlplane":
		fmt.Println("controlplane")

	case "dataplane":
		fmt.Println("dataplane")

	default:
		fmt.Fprintf(os.Stderr, "krouter: KROUTER_MODE must be 'controlplane' or 'dataplane' (got %q)\n", mode)
		os.Exit(64)
	}
}
