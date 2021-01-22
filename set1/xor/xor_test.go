package xor

import (
	"../hex"
	"../xor"

	"bytes"
	"testing"
)

func TestSum(t *testing.T) {
	t.Run("prob2", func(t *testing.T) {
		hexDecode := func(s string) []byte {
			d, err := hex.Decode(s)
			if err != nil {
				t.Fatal(err)
			}
			return d
		}

		addend1 := hexDecode("1c0111001f010100061a024b53535009181c")
		addend2 := hexDecode("686974207468652062756c6c277320657965")
		output := hexDecode("746865206b696420646f6e277420706c6179")

		if sum, err := xor.Sum(addend1, addend2); err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(sum, output) {
			t.Errorf("encoded != output")
		}
	})
}
