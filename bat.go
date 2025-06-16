package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"slices"
)

type Descriptor struct {
	Tag  byte
	Data []byte
}

type TransportStream struct {
	TransportStreamID    uint16
	OriginalNetworkID    uint16
	TransportDescriptors []Descriptor
}

type BATSection struct {
	BouquetID          uint16
	VersionNumber      byte
	SectionNumber      byte
	SectionLength      int
	Sections           []bool
	LastSectionNumber  byte
	BouquetDescriptors []Descriptor
	TransportStreams   []TransportStream
	TS                 map[int]TransportStream // Map to store Transport Streams by ID
}

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
var finalBATMap map[uint16]BATSection

// Funções para verificar se o pacote é NIT
func isNIT(packet []byte) bool {

	if len(packet) != packetSize || packet[0] != syncByte {
		return false
	}

	pid := int(packet[1]&0x1F)<<8 | int(packet[2])
	if pid != nitPID {
		return false
	}

	payloadStart := packet[1]&0x40 != 0
	adaptationFieldControl := (packet[3] >> 4) & 0x03
	payloadOffset := 4

	if adaptationFieldControl == 2 || adaptationFieldControl == 0 {
		return false // no payload
	}
	if adaptationFieldControl == 3 {
		adaptationFieldLength := int(packet[4])
		payloadOffset += 1 + adaptationFieldLength
	}

	if payloadStart {
		pointerField := int(packet[payloadOffset])
		payloadOffset += 1 + pointerField
	}

	if payloadOffset >= len(packet) {
		return false
	}

	tableID := packet[payloadOffset]
	return tableID == nitTableID
}

// Função para verificar se o pacote é BAT
func isBAT(packet []byte) bool {
	if len(packet) != packetSize || packet[0] != syncByte {
		return false
	}

	pid := int(packet[1]&0x1F)<<8 | int(packet[2])
	if pid != batPID {
		return false
	}

	payloadStart := packet[1]&0x40 != 0
	adaptationFieldControl := (packet[3] >> 4) & 0x03
	payloadOffset := 4

	if adaptationFieldControl == 2 || adaptationFieldControl == 0 {
		return false // no payload
	}
	if adaptationFieldControl == 3 {
		adaptationFieldLength := int(packet[4])
		payloadOffset += 1 + adaptationFieldLength
	}

	if payloadStart {
		pointerField := int(packet[payloadOffset])
		payloadOffset += 1 + pointerField
	}

	if payloadOffset >= len(packet) {
		return false
	}

	tableID := packet[payloadOffset]
	return tableID == batTableID
}

func extractPayload(packet []byte) ([]byte, bool) {
	if packet[0] != syncByte {
		return nil, false
	}
	pid := int(packet[1]&0x1F)<<8 | int(packet[2])
	if pid != batPID {
		return nil, false
	}
	adaptationFieldControl := (packet[3] >> 4) & 0x03
	if adaptationFieldControl == 0 || adaptationFieldControl == 2 {
		return nil, false
	}
	offset := 4
	if adaptationFieldControl == 3 {
		offset += int(packet[4]) + 1
	}
	return packet[offset:], packet[1]&0x40 != 0
}

func parseDescriptors(data []byte) ([]Descriptor, int) {
	var descriptors []Descriptor
	offset := 0
	for offset+2 <= len(data) {
		tag := data[offset]
		length := int(data[offset+1])
		if offset+2+length > len(data) {
			break
		}
		descriptors = append(descriptors, Descriptor{
			Tag:  tag,
			Data: data[offset+2 : offset+2+length],
		})
		offset += 2 + length
	}
	return descriptors, offset
}

func parseBATSection(section []byte) *BATSection {
	if len(section) < 8 || section[0] != batTableID {
		return nil
	}
	sectionLength := int(section[1]&0x0F)<<8 | int(section[2])
	if len(section) < 3+sectionLength {
		return nil
	}

	// SectionLength is set below in the returned struct
	bouquetID := binary.BigEndian.Uint16(section[3:5])
	versionNumber := (section[5] >> 1) & 0x1F
	sectionNumber := section[6]
	lastSectionNumber := section[7]

	bouquetDescriptorsLength := int(section[8]&0x0F)<<8 | int(section[9])
	bouquetDescriptors, _ := parseDescriptors(section[10 : 10+bouquetDescriptorsLength])

	tsLoopStart := 10 + bouquetDescriptorsLength
	tsLoopLength := int(section[tsLoopStart]&0x0F)<<8 | int(section[tsLoopStart+1])
	tsData := section[tsLoopStart+2 : tsLoopStart+2+tsLoopLength]

	var transportStreams []TransportStream
	offset := 0
	for offset+6 <= len(tsData) {
		tsID := binary.BigEndian.Uint16(tsData[offset : offset+2])
		onID := binary.BigEndian.Uint16(tsData[offset+2 : offset+4])
		descLen := int(tsData[offset+4]&0x0F)<<8 | int(tsData[offset+5])
		descStart := offset + 6
		descEnd := descStart + descLen
		if descEnd > len(tsData) {
			break
		}
		descriptors, _ := parseDescriptors(tsData[descStart:descEnd])
		transportStreams = append(transportStreams, TransportStream{
			TransportStreamID:    tsID,
			OriginalNetworkID:    onID,
			TransportDescriptors: descriptors,
		})
		offset = descEnd
	}

	return &BATSection{
		BouquetID:          bouquetID,
		VersionNumber:      versionNumber,
		SectionNumber:      sectionNumber,
		SectionLength:      sectionLength,
		LastSectionNumber:  lastSectionNumber,
		BouquetDescriptors: bouquetDescriptors,
		TransportStreams:   transportStreams,
	}
}

func processTsFile(filename string) {

	// Initialize the finalBATMap if it is nil
	if finalBATMap == nil {
		finalBATMap = make(map[uint16]BATSection)
	}

	// Process each packet in the TS file
	file, err := os.Open(filename)

	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}

	defer file.Close()

	buffer := make([]byte, packetSize)
	var sectionBuffer []byte
	var collecting bool
	var expectedLength int
	packetCounter := 0
	for {
		n, err := file.Read(buffer)
		if err != nil || n != packetSize {
			fmt.Println("End of file or read error:", err)
			break
		}
		packetCounter++

		payload, start := extractPayload(buffer)
		if payload == nil {
			//fmt.Printf("No valid payload found in packet %d, skipping...\n", packetCounter)
			continue
		}

		if start {
			if collecting && len(sectionBuffer) >= expectedLength {
				section := parseBATSection(sectionBuffer)
				if section == nil {
					continue
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
				collecting = false

				if addSectionToFinal(section) {
					// For test purposes, finish scanning after the first valid section
					break
				}
			}
		}
	}
	fmt.Println("Total packets processed:", packetCounter)

	// Finalizado parse da BAT
	fmt.Println("Processing TS file finished:", filename)
	section, exists := finalBATMap[25000]
	if exists {
		fmt.Printf("\nFinal BAT Section for Bouquet ID 25000:\n")
		fmt.Printf("Bouquet ID: %d, Version: %d, Section: %d/%d/%d\n", section.BouquetID, section.VersionNumber, section.SectionNumber, section.LastSectionNumber, section.SectionLength)
		for _, ts := range section.TransportStreams {
			fmt.Printf("\tTS ID: %d, ONID: %d, Descriptors: %d\n", ts.TransportStreamID, ts.OriginalNetworkID, len(ts.TransportDescriptors))
			for _, desc := range ts.TransportDescriptors {
				fmt.Printf("\t\tOTA Linkage Descriptor found 0x%x:\n", desc.Tag)
				fmt.Println(hex.Dump(desc.Data))
			}
		}
	} else {
		fmt.Println("No final BAT Section found for Bouquet ID 25000")
	}

	// Print all sections found
	fmt.Println("Total sections found:", len(finalBATMap))
	// Print Bouquet IDs in a compact, comma-separated format, 16 per line
	bouquetIDs := make([]uint16, 0, len(finalBATMap))
	for bouquetID := range finalBATMap {
		bouquetIDs = append(bouquetIDs, bouquetID)
	}

	// Optional: sort for consistent output
	slices.Sort(bouquetIDs)
	for i, bouquetID := range bouquetIDs {
		if i > 0 && i%16 != 0 {
			fmt.Printf("")
		}
		fmt.Printf("%d ", bouquetID)
		if (i+1)%16 == 0 {
			fmt.Println()
		}
	}

	// Print bouquet id 25000
	if section, exists := finalBATMap[25000]; exists {
		fmt.Printf("\nBouquet ID 25000 found with Version: %d, Section Number: %d, Last Section Number: %d\n", section.VersionNumber, section.SectionNumber, section.LastSectionNumber)

		counter := 0
		for _, ts := range section.TransportStreams {
			fmt.Printf("\t%d - Transport Stream ID: %d, Original Network ID: %d, Descriptors: %d\n", counter, ts.TransportStreamID, ts.OriginalNetworkID, len(ts.TransportDescriptors))
			for _, desc := range ts.TransportDescriptors {
				if desc.Tag == otaLinkageDescriptor {
					fmt.Printf("\t\tOTA Linkage Descriptor found 0x%x:\n", desc.Tag)
					fmt.Println(hex.Dump(desc.Data))
				}
			}
			counter++
		}

		fmt.Println()
		counter = 0
		for _, ts := range section.TS {
			fmt.Printf("\t%d - Transport Stream ID: %d, Original Network ID: %d, Descriptors: %d\n", counter, ts.TransportStreamID, ts.OriginalNetworkID, len(ts.TransportDescriptors))
			for _, desc := range ts.TransportDescriptors {
				if desc.Tag == otaLinkageDescriptor {
					fmt.Printf("\t\tOTA Linkage Descriptor found 0x%x:\n", desc.Tag)
					fmt.Println(hex.Dump(desc.Data))
				}
			}
			counter++
		}

	}

	fmt.Println("\nProcessing complete.")
}

func addSectionToFinal(section *BATSection) bool {

	// If the section is nil, do not add it
	if section == nil {
		return false
	}

	// for test purposes, only add sections with BouquetID 25000
	if section.BouquetID != 25000 {
		return false
	}

	// Check if the section is already in the final map
	_, exists := finalBATMap[section.BouquetID]
	if !exists {
		fmt.Println("Creating section:", section.BouquetID, "Version:", section.VersionNumber, "Section Number:", section.SectionNumber, "Last Section Number:", section.LastSectionNumber, "LastSectionNumber:", section.LastSectionNumber)

		for it := 0; it <= int(section.LastSectionNumber); it++ {
			section.Sections = append(section.Sections, false)
		}

		fmt.Println("Sections: ", section.LastSectionNumber)
		finalBATMap[section.BouquetID] = *section

		// Retrieve, modify, and store back to update fields in the map value
		tmp := finalBATMap[section.BouquetID]
		tmp.Sections[section.SectionNumber] = true
		tmp.TS = make(map[int]TransportStream)
		for _, ts := range section.TransportStreams {
			tmp.TS[int(ts.TransportStreamID)] = ts
		}
		finalBATMap[section.BouquetID] = tmp

	} else {

		mapPointer := finalBATMap[section.BouquetID]
		if mapPointer.Sections[section.SectionNumber] {
			fmt.Println("Section already exists:", section.SectionNumber)
		} else {
			fmt.Println("Updating section:", section.BouquetID, "Version:", section.VersionNumber, "Section Number:", section.SectionNumber, "Last Section Number:", section.LastSectionNumber)

			// Update the existing section
			mapPointer.TransportStreams = append(mapPointer.TransportStreams, section.TransportStreams...)
			mapPointer.Sections[section.SectionNumber] = true
			// Update the TS map with new Transport Streams
			for _, ts := range section.TransportStreams {
				if existingTS, exists := mapPointer.TS[int(ts.TransportStreamID)]; exists {
					// If the Transport Stream already exists, merge descriptors
					existingTS.TransportDescriptors = append(existingTS.TransportDescriptors, ts.TransportDescriptors...)
					mapPointer.TS[int(ts.TransportStreamID)] = existingTS
				} else {
					// If it doesn't exist, add it
					mapPointer.TS[int(ts.TransportStreamID)] = ts
				}
			}
			finalBATMap[section.BouquetID] = mapPointer
			fmt.Println("Section updated:", section.SectionNumber)
		}
	}

	// Verify if all sections are collected
	allSectionsCollected := true
	for sectionNumber := range finalBATMap[section.BouquetID].Sections {
		if !finalBATMap[section.BouquetID].Sections[sectionNumber] {
			fmt.Println("Section not collected:", sectionNumber)
			allSectionsCollected = false
			break
		}
		fmt.Println("Section collected:", sectionNumber)
	}
	return allSectionsCollected
}
