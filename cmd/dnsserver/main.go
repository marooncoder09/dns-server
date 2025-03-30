package main

import (
	"fmt"
	"net"

	"github.com/codecrafters-io/dns-server-starter-go/internal/dns"
)

func main() {
	fmt.Println("Logs from your program will appear here!")

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := buf[:size]
		header, err := dns.ParseHeader(receivedData)
		if err != nil {
			fmt.Println("Error parsing header:", err)
			continue
		}

		responseHeader := &dns.Header{
			ID:      header.ID,
			QR:      true,
			Opcode:  0,
			AA:      false,
			TC:      false,
			RD:      false,
			RA:      false,
			Z:       0,
			RCODE:   0,
			QDCOUNT: 0,
			ANCOUNT: 0,
			NSCOUNT: 0,
			ARCOUNT: 0,
		}

		response := responseHeader.Bytes()

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
