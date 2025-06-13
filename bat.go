package main

import "fmt"

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
		return true
	}

	return false
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
