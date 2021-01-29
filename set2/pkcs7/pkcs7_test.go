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

func TestUnpad(t *testing.T) {
	t.Run("prob15", func(t *testing.T) {
		input := []byte("ICE ICE BABY\x04\x04\x04\x04")
		var size uint = 16
		output := []byte("ICE ICE BABY")

		if unpadded, err := pkcs7.Unpad(input, size); err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(unpadded, output) {
			t.Errorf("unpadded != output")
		}
	})

	var failTests = []struct {
		input []byte
		size  uint
	}{
		{input:[]byte("ICE ICE BABY\x05\x05\x05\x05"), size:16},
		{input:[]byte("ICE ICE BABY\x01\x02\x03\x04"), size:16},
	}

	for _, test := range failTests {
		t.Run(string(test.input), func(t *testing.T) {
			if _, err := pkcs7.Unpad(test.input, test.size); err == nil {
				t.Errorf("err == nil")
			}
		})
	}
	
	var passTests = []struct {
		input  []byte
		size   uint
		output []byte
	}{
		{input:[]byte("\x04\x04\x04\x04"), size:4, output:[]byte("")},
		{input:[]byte("b\x03\x03\x03"), size:4, output:[]byte("b")},
		{input:[]byte("bl\x02\x02"), size:4, output:[]byte("bl")},
		{input:[]byte("blu\x01"), size:4, output:[]byte("blu")},
		{input:[]byte("blue\x04\x04\x04\x04"), size:4, output:[]byte("blue")},
	}

	for _, test := range passTests {
		t.Run(string(test.input), func(t *testing.T) {
			if unpadded, err := pkcs7.Unpad(test.input, test.size); err != nil {
				t.Fatal(err)
			} else if !bytes.Equal(unpadded, test.output) {
				t.Errorf("unpadded != output")
			}
		})
	}
}
