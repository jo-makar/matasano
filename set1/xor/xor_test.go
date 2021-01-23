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

func TestSumRepeat(t *testing.T) {
	t.Run("prob5", func(t *testing.T) {
		plaintext := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal\n")
		key := []byte("ICE")
		output := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f4f"

		ciphertext, _ := xor.SumRepeat(plaintext, key)
		if encoded, _ := hex.Encode(ciphertext); encoded != output {
			t.Errorf("encoded != output")
		}
	})
}
