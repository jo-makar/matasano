package ssrp

import (
	"../ssrp"

	"testing"
)

func TestVerify(t *testing.T) {
	t.Run("prob38", func(t *testing.T) {
		i, p := "user@host", "secret"
		if !ssrp.NewServer(i, p).VerifyClient(ssrp.NewClient(i, p)) {
			t.Errorf("incorrectly not verified")
		}

		if ssrp.NewServer(i, p).VerifyClient(ssrp.NewClient(i, p + "xyz")) {
			t.Errorf("incorrectly verified")
		}
	})
}
