package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
)

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

func ParseQuestion(data []byte, offset int) (Question, int, error) {
	name, offset, err := parseName(data, offset)
	if err != nil {
		return Question{}, 0, err
	}

	if offset+4 > len(data) {
		return Question{}, 0, errors.New("insufficient data for question")
	}

	q := Question{
		Name:  name,
		Type:  binary.BigEndian.Uint16(data[offset : offset+2]),
		Class: binary.BigEndian.Uint16(data[offset+2 : offset+4]),
	}

	return q, offset + 4, nil
}

func (q *Question) Bytes() []byte {
	var buf bytes.Buffer
	writeName(&buf, q.Name)
	binary.Write(&buf, binary.BigEndian, q.Type)
	binary.Write(&buf, binary.BigEndian, q.Class)
	return buf.Bytes()
}

func parseName(data []byte, offset int) (string, int, error) {
	var name bytes.Buffer
	initialOffset := offset
	ptrSeen := false

	for {
		if offset >= len(data) {
			return "", 0, errors.New("invalid name: offset out of bounds")
		}

		length := int(data[offset])
		offset++

		if length == 0 {
			break
		}

		// checking if this is a pointer (compression)
		if length&0xC0 == 0xC0 {
			if !ptrSeen {
				ptrSeen = true
				initialOffset = offset + 1 // saving where the pointer ends
			}
			ptrOffset := int(binary.BigEndian.Uint16([]byte{byte(length & 0x3F), data[offset]}))
			offset++
			part, _, err := parseName(data, ptrOffset)
			if err != nil {
				return "", initialOffset, err
			}
			name.WriteString(part)
			break
		}

		if offset+length > len(data) {
			return "", initialOffset, errors.New("invalid label length")
		}

		name.Write(data[offset : offset+length])
		name.WriteByte('.')
		offset += length
	}

	// removing the trailing dot if present (so that we can use it as a delimiter)
	strName := name.String()
	if len(strName) > 0 && strName[len(strName)-1] == '.' {
		strName = strName[:len(strName)-1]
	}

	return strName, offset, nil
}

func writeName(buf *bytes.Buffer, name string) {
	for _, part := range splitName(name) {
		buf.WriteByte(byte(len(part)))
		buf.WriteString(part)
	}
	buf.WriteByte(0) // terminating with a null byte
}

func splitName(name string) []string {
	return strings.Split(name, ".")
}
