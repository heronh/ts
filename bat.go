package main

import (
	"encoding/binary"
	"fmt"
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
	LastSectionNumber  byte
	BouquetDescriptors []Descriptor
	TransportStreams   []TransportStream
}

func processBatPacket(packet []byte) bool {

	if isBAT(packet) {
		// print packet data in hex
		fmt.Println()
		for _index, b := range packet {
			fmt.Printf("%02x ", b)
			if (_index+1)%32 == 0 {
				fmt.Println()
			}
		}
		fmt.Println()
	}

	return false
}

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
		LastSectionNumber:  lastSectionNumber,
		BouquetDescriptors: bouquetDescriptors,
		TransportStreams:   transportStreams,
	}
}
