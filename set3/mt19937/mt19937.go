package mt19937

type mt19937 struct {
    index uint
    state [624]uint32
}

func NewMt19937(x uint32) *mt19937 {
    m := new(mt19937)

    m.index = 0

    m.state[0] = x

    for i:=1; i<624; i++ {
        m.state[i] = 1812433253 * (m.state[i-1] ^ (m.state[i-1] >> 30)) + uint32(i)
    }

    return m
}

func (m *mt19937) Rand() uint32 {
    if m.index == 0 {
        for i:=0; i<624; i++ {
                var y uint32 = (m.state[i] & 0x80000000) + (m.state[(i+1) % 624] & 0x7fffffff)

                m.state[i] = m.state[(i + 397) % 624] ^ (y >> 1)
                if y % 2 != 0 {
                    m.state[i] = m.state[i] ^ 2567483615
                }
        }
    }

    var y uint32 = m.state[m.index]
    y ^= y >> 11
    y ^= (y << 7) & 2636928640
    y ^= (y << 15) & 4022730752
    y ^= y >> 18

    m.index = (m.index + 1) % 624
    return y
}
