package main

import (
	"encoding/hex"
	"fmt"
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

// Variável final para os pacotes BAT
var final []BATSection

func main() {

	if len(os.Args) < 2 {
		log.Fatal("Usage: go run main.go <filename.ts>")
	}

	file, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	buffer := make([]byte, packetSize)
	var sectionBuffer []byte
	var collecting bool
	var expectedLength int
	for {
		n, err := file.Read(buffer)
		if err != nil || n != packetSize {
			break
		}

		payload, start := extractPayload(buffer)
		if payload == nil {
			continue
		}

		if start {
			if collecting && len(sectionBuffer) >= expectedLength {
				section := parseBATSection(sectionBuffer)
				if section != nil {
					fmt.Printf("Parsed BAT Section: Bouquet ID: %d, Version: %d\n", section.BouquetID, section.VersionNumber)
					for _, ts := range section.TransportStreams {
						fmt.Printf("  TS ID: %d, ONID: %d, Descriptors: %d\n", ts.TransportStreamID, ts.OriginalNetworkID, len(ts.TransportDescriptors))
					}
				}
			}
			pointer := int(payload[0])
			payload = payload[1+pointer:]
			if len(payload) < 3 || payload[0] != batTableID {
				continue
			}
			sectionLength := int(payload[1]&0x0F)<<8 | int(payload[2])
			expectedLength = 3 + sectionLength
			sectionBuffer = make([]byte, 0, expectedLength)
			collecting = true
		}

		if collecting {
			sectionBuffer = append(sectionBuffer, payload...)
			if len(sectionBuffer) >= expectedLength {
				section := parseBATSection(sectionBuffer)
				if section != nil && section.BouquetID == 25008 {
					fmt.Printf("Parsed BAT Section: Bouquet ID: %d, Version: %d\n", section.BouquetID, section.VersionNumber)
					for _, ts := range section.TransportStreams {

						if ts.TransportStreamID != 24682 {
							continue
						}
						fmt.Printf("  TS ID: %d, ONID: %d, Descriptors: %d\n", ts.TransportStreamID, ts.OriginalNetworkID, len(ts.TransportDescriptors))
						for _, desc := range ts.TransportDescriptors {
							fmt.Printf("OTA Linkage Descriptor found 0x%X:\n", desc.Tag)
							fmt.Println(hex.Dump(desc.Data))
						}
					}
				}
				collecting = false
			}
		}
	}

	// Report final BAT sections
	fmt.Printf("Total BAT sections collected: %d\n", len(final))
}

// Open the TS file
/*
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
	fmt.Println("Finished reading BAT packets.")
	fmt.Printf("Total valid BAT packets processed: %d\n", validPacketCount)
*/
