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

func NewMt19937state(state []uint32) *mt19937 {
    m := new(mt19937)

    m.index = 0

    for i:=0; i<len(state); i++ {
        m.state[i] = state[i]
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

func Untemper(y4 uint32) uint32 {
    var m1 uint32 = 2636928640
    var m2 uint32 = 4022730752

    var y3, y2, y1, y0 uint32

    // y4 = y3 ^ (y3 >> 18)
    y3  = y4 & 0xfffc0000
    y3 |= ((y3 >> 18) ^ y4) & 0x0003ffff

    // y3 = y2 ^ ((y2 << 15) & m2)
    y2  = (y3 ^ m2) & 0x00007fff
    y2 |= (((y2 << 15) & m2) ^ y3) & 0x3fff8000
    y2 |= (((y2 << 15) & m2) ^ y3) & 0xc0000000

    // y2 = y1 ^ ((y1 << 7) & m1)
    y1  = (y2 ^ m1) & 0x0000007f
    y1 |= (((y1 << 7) & m1) ^ y2) & 0x00003f80
    y1 |= (((y1 << 7) & m1) ^ y2) & 0x001fc000
    y1 |= (((y1 << 7) & m1) ^ y2) & 0x0fe00000
    y1 |= (((y1 << 7) & m1) ^ y2) & 0xf0000000

    // y1 = y0 ^ (y0 >> 11)
    y0  = y1 & 0xffe00000
    y0 |= ((y0 >> 11) ^ y1) & 0x001ffc00
    y0 |= ((y0 >> 11) ^ y1) & 0x000003ff

    return y0
}
