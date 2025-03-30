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
	name, offset, err := ParseName(data, offset)
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

// Update parseName function to handle invalid labels
func ParseName(data []byte, offset int) (string, int, error) {
	var name bytes.Buffer
	initialOffset := offset
	maxJumps := 5
	jumps := 0

	for {
		if offset >= len(data) {
			return "", initialOffset, errors.New("invalid name: offset out of bounds")
		}

		length := int(data[offset])
		offset++

		if length == 0 {
			break
		}

		// Handle pointers (compression)
		if length&0xC0 == 0xC0 {
			if jumps >= maxJumps {
				return "", initialOffset, errors.New("too many jumps")
			}
			jumps++

			ptrOffset := int(binary.BigEndian.Uint16([]byte{byte(length & 0x3F), data[offset]}))
			offset++

			part, _, err := ParseName(data, ptrOffset)
			if err != nil {
				return "", initialOffset, err
			}
			name.WriteString(part)
			break
		}

		// Validate label length
		if length > 63 {
			return "", initialOffset, errors.New("invalid label length")
		}

		if offset+length > len(data) {
			return "", initialOffset, errors.New("invalid name: label exceeds buffer")
		}

		name.Write(data[offset : offset+length])
		name.WriteByte('.')
		offset += length
	}

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
