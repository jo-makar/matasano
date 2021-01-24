package pkcs7

import (
	"../pkcs7"

	"bytes"
	"testing"
)

func TestPad(t *testing.T) {
	t.Run("prob9", func(t *testing.T) {
		input := []byte("YELLOW SUBMARINE")
		var size uint = 20
		output := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")

		if padded, err := pkcs7.Pad(input, size); err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(padded, output) {
			t.Errorf("padded != output")
		}
	})

	var tests = []struct {
		input  []byte
		size   uint
		output []byte
	}{
		{input:[]byte(""), size:4, output:[]byte("\x04\x04\x04\x04")},
		{input:[]byte("b"), size:4, output:[]byte("b\x03\x03\x03")},
		{input:[]byte("bl"), size:4, output:[]byte("bl\x02\x02")},
		{input:[]byte("blu"), size:4, output:[]byte("blu\x01")},
		{input:[]byte("blue"), size:4, output:[]byte("blue\x04\x04\x04\x04")},
	}

	for _, test := range tests {
		t.Run(string(test.input), func(t *testing.T) {
			if padded, err := pkcs7.Pad(test.input, test.size); err != nil {
				t.Fatal(err)
			} else if !bytes.Equal(padded, test.output) {
				t.Errorf("padded != output")
			}
		})
	}
}
