package dns

import (
	"encoding/binary"
	"fmt"
)

const (
	HeaderSize = 12
	QRResponse = 1 << 7 // (10000000): [here we are setting the 8th bit to 1 by left shifting 1 by 7 positions]
)

type Header struct {
	ID uint16 // this helps match requests with responses

	QR bool // query / response flag 0 = query, 1 = response, helps to distinguish between requests and responses

	Opcode uint8 // operation code, specifies the type of query:
	// 0 = standard query (most common)
	// 1 = inverse query (obsolete)
	// 2 = server status request (rarely used)
	// 3-15 = reserved for future use.

	AA bool // authoritative answer, indicates if the responding server is authoritative for the domain (valid only in responses)

	TC bool // truncation, indicates if the message was truncated due to size limitations (512 bytes for UDP)

	RD bool // recursion desired, set by the client if it wants the server to resolve the query recursively (i.e., follow CNAMEs, etc.)

	RA bool // recursion available, set by the server to indicate that it supports recursive querying (valid only in responses)

	Z uint8 // reserved for future use, must be zero in queries and responses, (the future use is for DNSSEC: https://www.cloudflare.com/en-gb/learning/dns/dnssec/how-dnssec-works/)

	RCODE uint8 // response code, indicates the status of the response:
	// 0 = no error
	// 1 = format error (query was malformed)
	// 2 = server failure (server unable to process due to an internal error)
	// 3 = name error (non-existent domain; only valid for authoritative servers)
	// 4 = not implemented (query type not supported)
	// 5 = refused (server refuses to perform the operation)
	// 6-15 = reserved for future use.

	QDCOUNT uint16 // number of entries in the question section, usually 1 for most queries

	ANCOUNT uint16 // number of resource records in the answer section, 0 if no answers are found

	NSCOUNT uint16 // number of resource records in the authority section, provides information about authoritative nameservers

	ARCOUNT uint16 // number of resource records in the additional section, provides extra information related to the query
}

/*

should refer to the following resources:
1. RFC 1035 (Domain Names - Implementation and Specification):
   - https://datatracker.ietf.org/doc/html/rfc1035 (focus on section 4.1.1 for header fields description)

2. DNS Packet Format Explanation:
   - https://www.cloudflare.com/en-gb/learning/dns/dns-records/

3. Understanding DNS Messages:
   - https://www.ibm.com/products/ns1-connect

*/

func ParseHeader(data []byte) (*Header, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("header too short")
	}

	h := &Header{}
	h.ID = binary.BigEndian.Uint16(data[0:2])

	flags1 := data[2]
	flags2 := data[3]

	h.QR = (flags1>>7)&1 == 1
	h.Opcode = (flags1 >> 3) & 0x0F
	h.AA = (flags1>>2)&1 == 1
	h.TC = (flags1>>1)&1 == 1
	h.RD = flags1&1 == 1

	h.RA = (flags2>>7)&1 == 1
	h.Z = (flags2 >> 4) & 0x07
	h.RCODE = flags2 & 0x0F

	h.QDCOUNT = binary.BigEndian.Uint16(data[4:6])
	h.ANCOUNT = binary.BigEndian.Uint16(data[6:8])
	h.NSCOUNT = binary.BigEndian.Uint16(data[8:10])
	h.ARCOUNT = binary.BigEndian.Uint16(data[10:12])

	return h, nil
}

func (h *Header) Bytes() []byte {
	data := make([]byte, 12)
	binary.BigEndian.PutUint16(data[0:2], h.ID)

	var flags1 byte
	if h.QR {
		flags1 |= 1 << 7
	}
	flags1 |= (h.Opcode & 0x0F) << 3
	if h.AA {
		flags1 |= 1 << 2
	}
	if h.TC {
		flags1 |= 1 << 1
	}
	if h.RD {
		flags1 |= 1
	}
	data[2] = flags1

	var flags2 byte
	if h.RA {
		flags2 |= 1 << 7
	}
	flags2 |= (h.Z & 0x07) << 4
	flags2 |= h.RCODE & 0x0F
	data[3] = flags2

	binary.BigEndian.PutUint16(data[4:6], h.QDCOUNT)
	binary.BigEndian.PutUint16(data[6:8], h.ANCOUNT)
	binary.BigEndian.PutUint16(data[8:10], h.NSCOUNT)
	binary.BigEndian.PutUint16(data[10:12], h.ARCOUNT)

	return data
}
