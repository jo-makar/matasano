package hamming

import (
	"../hamming"

	"testing"
)

func TestDist(t *testing.T) {
	t.Run("prob6-ex", func(t *testing.T) {
		operand1 := []byte("this is a test")
		operand2 := []byte("wokka wokka!!!")
		var output uint = 37

		if dist := hamming.Dist(operand1, operand2); dist != output {
			t.Errorf("dist != output")
		}
	})
}
