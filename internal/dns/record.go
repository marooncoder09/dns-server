package dns

import (
	"bytes"
	"encoding/binary"
	"net"
)

type ResourceRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte
}

func (rr *ResourceRecord) Bytes() []byte {
	var buf bytes.Buffer
	writeName(&buf, rr.Name)
	binary.Write(&buf, binary.BigEndian, rr.Type)
	binary.Write(&buf, binary.BigEndian, rr.Class)
	binary.Write(&buf, binary.BigEndian, rr.TTL)
	binary.Write(&buf, binary.BigEndian, uint16(len(rr.Data)))
	buf.Write(rr.Data)
	return buf.Bytes()
}

func CreateAnswer(name string, ip string) ResourceRecord {
	return ResourceRecord{
		Name:  name,
		Type:  1, // A record
		Class: 1, // IN class
		TTL:   60,
		Data:  net.ParseIP(ip).To4(),
	}
}
