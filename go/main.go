package main

import (
	"log"
	"os"
)

func main() {

	if len(os.Args) < 2 {
		log.Fatal("Usage: go run main.go <filename.ts>")
	}

	// Verify if the file exists
	if _, err := os.Stat(os.Args[1]); os.IsNotExist(err) {
		log.Fatalf("File does not exist: %s", os.Args[1])
	}

	// Process the TS file
	processTsFile(os.Args[1])
}
