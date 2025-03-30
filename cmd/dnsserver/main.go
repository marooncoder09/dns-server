package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/codecrafters-io/dns-server-starter-go/internal/dns"
)

const (
	PORT    = "2053"
	IP      = "127.0.0.1"
	TIMEOUT = 2 * time.Second
)

var resolverAddr string

func main() {
	flag.StringVar(&resolverAddr, "resolver", "", "Upstream DNS resolver address (ip:port)")
	flag.Parse()

	if resolverAddr == "" {
		fmt.Println("Error: --resolver flag is required")
		os.Exit(1)
	}

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

		go handleRequest(udpConn, source, buf[:size])
	}
}

func handleRequest(conn *net.UDPConn, clientAddr *net.UDPAddr, requestData []byte) {
	queryHeader, err := dns.ParseHeader(requestData)
	if err != nil {
		fmt.Println("Error parsing header:", err)
		return
	}

	questions := parseQuestions(requestData, queryHeader.QDCOUNT)
	if len(questions) == 0 {
		fmt.Println("No questions in query")
		return
	}

	var responses [][]byte
	for _, q := range questions {
		response, err := forwardToResolver(q, resolverAddr, queryHeader)

		if err != nil {
			fmt.Println("Error forwarding query:", err)
			continue
		}
		responses = append(responses, response)
	}

	if len(responses) == 0 {
		return
	}

	response := mergeResponses(queryHeader.ID, queryHeader, responses)
	_, err = conn.WriteToUDP(response, clientAddr)
	if err != nil {
		fmt.Println("Failed to send response:", err)
	}
}

func forwardToResolver(q dns.Question, resolverIP string, originalHeader *dns.Header) ([]byte, error) {
	queryHeader := &dns.Header{
		ID:      dns.GenerateID(),
		QR:      false,
		Opcode:  originalHeader.Opcode,
		AA:      false,
		TC:      false,
		RD:      originalHeader.RD,
		RA:      false,
		Z:       0,
		RCODE:   0,
		QDCOUNT: 1,
		ANCOUNT: 0,
		NSCOUNT: 0,
		ARCOUNT: 0,
	}

	var buf bytes.Buffer
	buf.Write(queryHeader.Bytes())
	buf.Write(q.Bytes())

	resolverConn, err := net.DialTimeout("udp", resolverAddr, TIMEOUT)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to resolver: %v", err)
	}
	defer resolverConn.Close()

	resolverConn.SetWriteDeadline(time.Now().Add(TIMEOUT))
	_, err = resolverConn.Write(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to send query to resolver: %v", err)
	}

	resolverConn.SetReadDeadline(time.Now().Add(TIMEOUT))
	response := make([]byte, 512)
	n, err := resolverConn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read response from resolver: %v", err)
	}

	return response[:n], nil
}

func mergeResponses(originalID uint16, originalHeader *dns.Header, responses [][]byte) []byte {
	if len(responses) == 1 {
		response := responses[0]
		response[0] = byte(originalID >> 8)
		response[1] = byte(originalID & 0xFF)
		return response
	}

	var questions []dns.Question
	var answers []dns.ResourceRecord

	for _, resp := range responses {
		header, _ := dns.ParseHeader(resp)
		qs := parseQuestions(resp, header.QDCOUNT)
		questions = append(questions, qs...)

		offset := dns.HeaderSize

		for i := 0; i < int(header.QDCOUNT); i++ {
			_, newOffset, err := dns.ParseQuestion(resp, offset)
			if err != nil {
				break
			}
			offset = newOffset
		}

		for i := 0; i < int(header.ANCOUNT); i++ {
			name, newOffset, err := dns.ParseName(resp, offset)
			if err != nil {
				break
			}

			if newOffset+10 > len(resp) {
				break
			}

			rr := dns.ResourceRecord{
				Name:  name,
				Type:  binary.BigEndian.Uint16(resp[newOffset : newOffset+2]),
				Class: binary.BigEndian.Uint16(resp[newOffset+2 : newOffset+4]),
				TTL:   binary.BigEndian.Uint32(resp[newOffset+4 : newOffset+8]),
			}

			rdLength := binary.BigEndian.Uint16(resp[newOffset+8 : newOffset+10])
			newOffset += 10

			if newOffset+int(rdLength) > len(resp) {
				break
			}

			rr.Data = resp[newOffset : newOffset+int(rdLength)]
			answers = append(answers, rr)
			offset = newOffset + int(rdLength)
		}
	}

	responseHeader := &dns.Header{
		ID:      originalID,
		QR:      true,
		Opcode:  originalHeader.Opcode,
		AA:      false,
		TC:      false,
		RD:      originalHeader.RD,
		RA:      false,
		Z:       0,
		RCODE:   0,
		QDCOUNT: uint16(len(questions)),
		ANCOUNT: uint16(len(answers)),
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
