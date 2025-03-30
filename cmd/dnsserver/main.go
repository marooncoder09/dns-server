package main

import (
	"bytes"
	"fmt"
	"net"
	"os"

	"github.com/codecrafters-io/dns-server-starter-go/internal/dns"
)

const (
	PORT    = "2053"
	IP      = "127.0.0.1"
	ID      = 1234
	OPCODE  = 0
	AA      = false
	TC      = false
	RD      = false
	RA      = false
	Z       = 0
	RCODE   = 0
	QDCOUNT = 1
	ANCOUNT = 0
	NSCOUNT = 0
	ARCOUNT = 0
)

func main() {
	fmt.Println("Logs from your program will appear here!")

	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%s", IP, PORT))
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		os.Exit(1)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		os.Exit(1)
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			continue
		}

		receivedData := buf[:size]

		queryHeader, err := dns.ParseHeader(receivedData)
		if err != nil {
			fmt.Println("Error parsing header:", err)
			continue
		}

		questions := parseQuestions(receivedData, queryHeader.QDCOUNT)
		if len(questions) == 0 {
			fmt.Println("No questions in query")
			continue
		}

		response := buildResponse(queryHeader, questions)

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
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
	answers := make([]dns.ResourceRecord, 0)

	for _, q := range questions {
		if q.Type == 1 && q.Class == 1 {
			answers = append(answers, dns.CreateAnswer(q.Name, "8.8.8.8"))
		}
	}

	rcode := uint8(0)
	if queryHeader.Opcode != 0 {
		rcode = 4
	}

	responseHeader := &dns.Header{
		ID:      queryHeader.ID,
		QR:      true,
		Opcode:  queryHeader.Opcode,
		AA:      false,
		TC:      false,
		RD:      queryHeader.RD,
		RA:      false,
		Z:       0,
		RCODE:   rcode,
		QDCOUNT: uint16(len(questions)),
		ANCOUNT: uint16(len(answers)), // this should match thenmbers of
		NSCOUNT: 0,
		ARCOUNT: 0,
	}

	var buf bytes.Buffer
	buf.Write(responseHeader.Bytes())

	for _, q := range questions {
		buf.Write(q.Bytes())
	}

	for _, a := range answers {
		buf.Write(a.Bytes())
	}

	return buf.Bytes()
}
