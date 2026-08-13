package main

import (
	"fmt"
	"os"

	"github.com/legion/go-tun/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "gotun: %v\n", err)
		os.Exit(1)
	}
}
