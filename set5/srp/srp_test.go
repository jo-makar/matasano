package srp

import (
	"../srp"

	"testing"
)

func TestVerify(t *testing.T) {
	t.Run("prob36", func(t *testing.T) {
		i, p := "user@host", "secret"
		if !srp.NewServer(i, p).VerifyClient(srp.NewClient(i, p)) {
			t.Errorf("incorrectly not verified")
		}

		if srp.NewServer(i, p).VerifyClient(srp.NewClient(i, p + "xyz")) {
			t.Errorf("incorrectly verified")
		}
	})
}
