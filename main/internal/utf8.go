package utf8

import "fmt"

// DecodeUTF8CodepointsToRawBytes parses a UTF-8 string as a raw byte array.
// That is to say, each codepoint in the Unicode string will be treated as a
// single byte (must be in range 0x00 ~ 0xff).
//
// If a codepoint falls out of the range, an error will be returned.
func DecodeUTF8CodepointsToRawBytes(utf8Str string) ([]byte, error) {
	runes := []rune(utf8Str)
	rawBytes := make([]byte, len(runes))
	for i, r := range runes {
		if (r & 0xFF) != r {
			return nil, fmt.Errorf("character out of range: %d", r)
		}
		rawBytes[i] = byte(r)
	}
	return rawBytes, nil
}
