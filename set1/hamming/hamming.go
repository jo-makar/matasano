package hamming

func Dist(a, b []byte) uint {
	var dist uint

	var min int
	if len(a) < len(b) {
		min = len(a)
		dist += uint(len(b)-len(a)) * 8
	} else {
		min = len(b)
		dist += uint(len(a)-len(b)) * 8
	}

	for i := 0; i < min; i++ {
		v := a[i] ^ b[i]
		for j := uint(0); j < 8; j++ {
			if v & (1<<j) != 0 {
				dist++
			}
		}
	}

	return dist
}
