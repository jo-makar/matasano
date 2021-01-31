package mt19937

type Mt19937 struct {
	index uint
	state [624]uint32
}

func NewMt19937Seed(seed uint32) *Mt19937 {
	m := Mt19937{}

	m.state[0] = seed
	for i := 1; i < len(m.state); i++ {
		m.state[i] = 1812433253 * (m.state[i-1] ^ (m.state[i-1] >> 30)) + uint32(i)
	}

	return &m
}

func NewMt19937State(index uint, state []uint32) *Mt19937 {
	m := Mt19937{}

	m.index = index
	for i := 0; i < len(state); i++ {
		m.state[i] = state[i]
	}
	for j := len(state); j < len(m.state); j++ {
		m.state[j] = 1812433253 * (m.state[j-1] ^ (m.state[j-1] >> 30)) + uint32(j)
	}

	return &m
}

func (m *Mt19937) Uint32() uint32 {
	if m.index == 0 {
		for i := 0; i < len(m.state); i++ {
			var y uint32 = (m.state[i] & 0x80000000) + (m.state[(i+1) % len(m.state)] & 0x7fffffff)

			m.state[i] = m.state[(i + 397) % len(m.state)] ^ (y >> 1)
			if y % 2 != 0 {
				m.state[i] ^= 2567483615
			}
		}
	}

	var y uint32 = m.state[m.index]
	y ^= y >> 11
	y ^= (y << 7) & 2636928640
	y ^= (y << 15) & 4022730752
	y ^= y >> 18

	m.index = (m.index + 1) % uint(len(m.state))
	return y
}
