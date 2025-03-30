package server

import (
	"fmt"
	"net"

	"github.com/codecrafters-io/dns-server-starter-go/internal/dns"
)

type Handler struct {
	Forwarder *Forwarder
}

func NewHandler(resolverAddr string) *Handler {
	return &Handler{
		Forwarder: NewForwarder(resolverAddr),
	}
}

func (h *Handler) HandleRequest(conn *net.UDPConn, clientAddr *net.UDPAddr, requestData []byte) {
	queryHeader, err := dns.ParseHeader(requestData)
	if err != nil {
		fmt.Printf("Error parsing header: %v\n", err)
		return
	}

	questions := dns.ParseQuestions(requestData, queryHeader.QDCOUNT)
	if len(questions) == 0 {
		fmt.Println("No questions in query")
		return
	}

	var responses [][]byte
	for _, q := range questions {
		response, err := h.Forwarder.Forward(q, queryHeader)
		if err != nil {
			fmt.Printf("Error forwarding query: %v\n", err)
			continue
		}
		responses = append(responses, response)
	}

	if len(responses) == 0 {
		return
	}

	response := MergeResponses(queryHeader, responses)
	if _, err := conn.WriteToUDP(response, clientAddr); err != nil {
		fmt.Printf("Failed to send response: %v\n", err)
	}
}
