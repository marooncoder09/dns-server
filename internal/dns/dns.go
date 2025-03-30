package dns

import (
	"math/rand"
	"time"
)

func GenerateID() uint16 {
	rand.Seed(time.Now().UnixNano())
	return uint16(rand.Intn(65535)) // generate a random number between 0 and 65535
}
