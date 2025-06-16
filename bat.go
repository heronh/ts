package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
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
	LastSectionNumber  byte
	BouquetDescriptors []Descriptor
	TransportStreams   []TransportStream
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
var finalBATSection []BATSection
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

	// Initialize finalBATSection
	finalBATSection = make([]BATSection, 0)

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
		fmt.Printf("Processing packet %d\n", packetCounter)

		if start {
			if collecting && len(sectionBuffer) >= expectedLength {
				section := parseBATSection(sectionBuffer)
				if section != nil {
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
			fmt.Println("Collecting BAT section detected at packet", packetCounter)
			sectionBuffer = append(sectionBuffer, payload...)
			if len(sectionBuffer) >= expectedLength {
				section := parseBATSection(sectionBuffer)
				addSectionToFinal(section)
				collecting = false
			}
		}
	}

	// Finalizado parse da BAT
	fmt.Println("Processing TS file finished:", filename)
	section, exists := finalBATMap[25008]
	if exists {
		fmt.Printf("\nFinal BAT Section for Bouquet ID 25008:\n")
		fmt.Printf("Bouquet ID: %d, Version: %d, Section: %d/%d/%d\n", section.BouquetID, section.VersionNumber, section.SectionNumber, section.LastSectionNumber, section.SectionLength)
		for _, ts := range section.TransportStreams {
			if ts.TransportStreamID == 24682 {
				fmt.Printf("\tTS ID: %d, ONID: %d, Descriptors: %d\n", ts.TransportStreamID, ts.OriginalNetworkID, len(ts.TransportDescriptors))
				for _, desc := range ts.TransportDescriptors {
					fmt.Printf("\t\tOTA Linkage Descriptor found 0x%x:\n", desc.Tag)
					fmt.Println(hex.Dump(desc.Data))
				}
			}
		}
	} else {
		fmt.Println("No final BAT Section found for Bouquet ID 25008")
	}

}

func addSectionToFinal(section *BATSection) {

	// If the section is nil, do not add it
	if section == nil {
		return
	}

	// Initialize the finalBATMap if it is nil
	if finalBATMap == nil {
		finalBATMap = make(map[uint16]BATSection)
	}

	// Check if the section is already in the final map
	_, exists := finalBATMap[section.BouquetID]
	if !exists {
		finalBATMap[section.BouquetID] = *section
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
