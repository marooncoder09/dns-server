package main

import (
	"bytes"
	"fmt"
	"net"

	"github.com/codecrafters-io/dns-server-starter-go/internal/dns"
)

func main() {
	fmt.Println("Logs from your program will appear here!")

	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	udpConn, _ := net.ListenUDP("udp", udpAddr)
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, _ := udpConn.ReadFromUDP(buf)
		receivedData := buf[:size]

		header, _ := dns.ParseHeader(receivedData)
		questions := parseQuestions(receivedData, header.QDCOUNT)

		response := buildResponse(header, questions)

		udpConn.WriteToUDP(response, source)
	}
}

func parseQuestions(data []byte, count uint16) []dns.Question {
	var questions []dns.Question
	offset := dns.HeaderSize

	for i := 0; i < int(count); i++ {
		q, newOffset, err := dns.ParseQuestion(data, offset)
		if err != nil {
			break
		}
		questions = append(questions, q)
		offset = newOffset
	}

	return questions
}

func buildResponse(queryHeader *dns.Header, questions []dns.Question) []byte {
	responseHeader := &dns.Header{
		ID:      queryHeader.ID,
		QR:      true,
		Opcode:  queryHeader.Opcode,
		AA:      false,
		TC:      false,
		RD:      queryHeader.RD,
		RA:      false,
		Z:       0,
		RCODE:   0,
		QDCOUNT: uint16(len(questions)),
		ANCOUNT: 0,
		NSCOUNT: 0,
		ARCOUNT: 0,
	}

	var buf bytes.Buffer
	buf.Write(responseHeader.Bytes())

	for _, q := range questions {
		buf.Write(q.Bytes())
	}

	return buf.Bytes()
}
