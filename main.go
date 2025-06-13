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
var finalBATSection []BATSection

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
				addSectionToFinal(section)
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

	// order finalBATSection by Bouquet ID
	for i := 0; i < len(finalBATSection)-1; i++ {
		for j := i + 1; j < len(finalBATSection); j++ {
			if finalBATSection[i].BouquetID > finalBATSection[j].BouquetID {
				finalBATSection[i], finalBATSection[j] = finalBATSection[j], finalBATSection[i]
			}
		}
	}
	fmt.Println("Final BAT Sections:")
	for _, section := range finalBATSection {

		if section.BouquetID != 25008 {
			continue
		}

		fmt.Printf("\nBouquet ID: %d, Version: %d, Section: %d/%d\n", section.BouquetID, section.VersionNumber, section.SectionNumber, section.LastSectionNumber)
		for _, ts := range section.TransportStreams {
			fmt.Printf("\tTS ID: %d, ONID: %d, Descriptors: %d\n", ts.TransportStreamID, ts.OriginalNetworkID, len(ts.TransportDescriptors))
			for _, desc := range ts.TransportDescriptors {
				if desc.Tag == otaLinkageDescriptor {
					fmt.Printf("\t\tOTA Linkage Descriptor found %d:\n\t\t", desc.Tag)
					fmt.Println(hex.Dump(desc.Data))
				}
			}
		}
		for _, desc := range section.BouquetDescriptors {
			if desc.Tag == otaLinkageDescriptor {
				fmt.Printf("\tOTA Linkage Descriptor found in Bouquet Descriptors 0x%X:\n\t\t", desc.Tag)
				fmt.Println(hex.Dump(desc.Data))
			}
		}
		break
	}

}

func addSectionToFinal(section *BATSection) {

	// If the section is nil, do not add it
	if section == nil {
		return
	}

	// Check if the section with same bouquetid exists in the final list
	found := false
	for _, existingSection := range finalBATSection {
		if existingSection.BouquetID == section.BouquetID {
			found = true
			break
		}
	}

	if !found {
		// Create a new empty final section
		newSection := BATSection{
			BouquetID:         section.BouquetID,
			VersionNumber:     section.VersionNumber,
			SectionNumber:     section.SectionNumber,
			LastSectionNumber: section.LastSectionNumber,
			//BouquetDescriptors: section.BouquetDescriptors,
			//TransportStreams: section.TransportStreams,
		}
		finalBATSection = append(finalBATSection, newSection)
	}

	// Create a pointer to section of this bouquetid
	var finalSection *BATSection
	for i := range finalBATSection {
		if finalBATSection[i].BouquetID == section.BouquetID {
			finalSection = &finalBATSection[i]
			break
		}
	}

	// Check each BouquetDescriptor and append it to the final section
	found = false
	for _, desc := range section.BouquetDescriptors {
		if desc.Tag == otaLinkageDescriptor {
			found = true
			finalSection.BouquetDescriptors = append(finalSection.BouquetDescriptors, desc)
		}
	}

	if !found {
		fmt.Printf("No OTA Linkage Descriptor found in Bouquet Descriptors for Bouquet ID %d\n", section.BouquetID)
	}

	// Check each TransportStream and append it to the final section
	for _, ts := range section.TransportStreams {
		found = false
		for _, existingTS := range finalSection.TransportStreams {
			if existingTS.TransportStreamID == ts.TransportStreamID && existingTS.OriginalNetworkID == ts.OriginalNetworkID {
				found = true
				break
			}
		}

		if !found {
			newTS := TransportStream{
				TransportStreamID:    ts.TransportStreamID,
				OriginalNetworkID:    ts.OriginalNetworkID,
				TransportDescriptors: ts.TransportDescriptors,
			}
			finalSection.TransportStreams = append(finalSection.TransportStreams, newTS)
		} else {
			fmt.Printf("Transport Stream ID %d already exists in final section for Bouquet ID %d\n", ts.TransportStreamID, section.BouquetID)
		}
	}
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
