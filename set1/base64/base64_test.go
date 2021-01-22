package base64

import (
	"../base64"
	"../hex"

	"testing"
)

func TestEncode(t *testing.T) {
	t.Run("prob1", func(t *testing.T) {
		input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
		output := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

		 if decoded, err := hex.Decode(input); err != nil {
			t.Fatal(err)
		 } else {
			t.Logf("decoded = %q", decoded)
			if encoded, err := base64.Encode(decoded); err != nil {
				t.Fatal(err)
			} else if encoded != output {
				t.Errorf("encoded != output")
			}
		 }
	})

	var tests = []struct{
		input  []byte
		output string
	}{
		{input:[]byte("any carnal pleasure."), output:"YW55IGNhcm5hbCBwbGVhc3VyZS4="},
		{input:[]byte("any carnal pleasure"),  output:"YW55IGNhcm5hbCBwbGVhc3VyZQ=="},
		{input:[]byte("any carnal pleasur"),   output:"YW55IGNhcm5hbCBwbGVhc3Vy"},
		{input:[]byte("any carnal pleasu"),    output:"YW55IGNhcm5hbCBwbGVhc3U="},
		{input:[]byte("any carnal pleas"),     output:"YW55IGNhcm5hbCBwbGVhcw=="},

		{input:[]byte("pleasure."), output:"cGxlYXN1cmUu"},
		{input:[]byte("leasure."),  output:"bGVhc3VyZS4="},
		{input:[]byte("easure."),   output:"ZWFzdXJlLg=="},
		{input:[]byte("asure."),    output:"YXN1cmUu"},
		{input:[]byte("sure."),     output:"c3VyZS4="},
	}

	for _, test := range tests {
		t.Run(string(test.input), func(t *testing.T) {
			if encoded, err := base64.Encode(test.input); err != nil {
				t.Fatal(err)
			} else if encoded != test.output {
				t.Errorf("encoded != output")
			}
		})
	}
}
