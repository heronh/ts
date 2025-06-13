package main

import (
	"fmt"
	"io"
	"log"
	"os"
)

const (
	packetSize           = 188
	syncByte             = 0x47
	batPID               = 0x0011
	batTableID           = 0x4A
	nitPID               = 0x0010
	nitTableID           = 0x40
	otaLinkageDescriptor = 0x09
)

var file *os.File

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run main.go <filename.ts>")
	}

	filename := os.Args[1]
	fmt.Printf("Reading and parsing BAT sections from '%s'...\n", filename)

	// Open the TS file
	var err error
	file, err = os.Open(filename)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	// Read and parse the BAT sections
	validPacketCount := 0
	for i := range 1000 {
		// Read a packet
		packet := make([]byte, packetSize)
		_, err := file.Read(packet)
		if err == io.EOF {
			fmt.Println("Reached end of file.")
			break
		}
		if processBatPacket(packet) {
			fmt.Printf("BAT packet %d processed successfully.\n", i+1)
			validPacketCount++
		}
	}
	fmt.Println("Finished reading BAT sections.")
	fmt.Printf("Total valid BAT packets processed: %d\n", validPacketCount)
}
