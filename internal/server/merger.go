package server

import (
	"bytes"
	"encoding/binary"

	"github.com/codecrafters-io/dns-server-starter-go/internal/dns"
)

func MergeResponses(originalHeader *dns.Header, responses [][]byte) []byte {
	if len(responses) == 1 {
		return fixResponseID(originalHeader.ID, responses[0])
	}

	questions, answers := parseResponses(responses)
	return buildFinalResponse(originalHeader, questions, answers)
}

func fixResponseID(originalID uint16, response []byte) []byte {
	response[0] = byte(originalID >> 8)
	response[1] = byte(originalID & 0xFF)
	return response
}

func parseResponses(responses [][]byte) ([]dns.Question, []dns.ResourceRecord) {
	var questions []dns.Question
	var answers []dns.ResourceRecord

	for _, resp := range responses {
		header, _ := dns.ParseHeader(resp)
		questions = append(questions, dns.ParseQuestions(resp, header.QDCOUNT)...)
		answers = append(answers, parseAnswers(resp, header.ANCOUNT)...)
	}
	return questions, answers
}

func parseAnswers(data []byte, count uint16) []dns.ResourceRecord {
	var answers []dns.ResourceRecord
	offset := dns.HeaderSize

	// Skip questions
	for i := 0; i < int(count); i++ {
		_, newOffset, _ := dns.ParseQuestion(data, offset)
		offset = newOffset
	}

	// Parse answers
	for i := 0; i < int(count); i++ {
		name, newOffset, _ := dns.ParseName(data, offset)
		if newOffset+10 > len(data) {
			break
		}

		rr := dns.ResourceRecord{
			Name:  name,
			Type:  binary.BigEndian.Uint16(data[newOffset : newOffset+2]),
			Class: binary.BigEndian.Uint16(data[newOffset+2 : newOffset+4]),
			TTL:   binary.BigEndian.Uint32(data[newOffset+4 : newOffset+8]),
		}

		rdLength := binary.BigEndian.Uint16(data[newOffset+8 : newOffset+10])
		newOffset += 10
		rr.Data = data[newOffset : newOffset+int(rdLength)]
		answers = append(answers, rr)
		offset = newOffset + int(rdLength)
	}
	return answers
}

func buildFinalResponse(header *dns.Header, questions []dns.Question, answers []dns.ResourceRecord) []byte {
	responseHeader := &dns.Header{
		ID:      header.ID,
		QR:      true,
		Opcode:  header.Opcode,
		AA:      false,
		TC:      false,
		RD:      header.RD,
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
