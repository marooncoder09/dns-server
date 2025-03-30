package server

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/codecrafters-io/dns-server-starter-go/internal/dns"
)

const timeout = 2 * time.Second

type Forwarder struct {
	ResolverAddr string
}

func NewForwarder(resolverAddr string) *Forwarder {
	return &Forwarder{ResolverAddr: resolverAddr}
}

func (f *Forwarder) Forward(q dns.Question, originalHeader *dns.Header) ([]byte, error) {
	query := buildForwardQuery(q, originalHeader)

	conn, err := net.DialTimeout("udp", f.ResolverAddr, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to resolver: %w", err)
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("failed to send query: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return response[:n], nil
}

func buildForwardQuery(q dns.Question, header *dns.Header) []byte {
	queryHeader := &dns.Header{
		ID:      dns.GenerateID(),
		QR:      false,
		Opcode:  header.Opcode,
		AA:      false,
		TC:      false,
		RD:      header.RD,
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
	return buf.Bytes()
}
