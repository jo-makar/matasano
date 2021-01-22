package score

import (
	"../hex"

	"bufio"
	"errors"
	"io"
	"math"
)

type Table struct {
	Data map[string]float32
}

// Table of n-length string occurrence [percentage] from a corpus
func NewTable(reader io.Reader, n uint) (*Table, error) {
	if n == 0 {
		return nil, errors.New("NewTable: n == 0")
	}

	// Similar to bufio.ScanBytes but by n-byte tokens with n>=1
	scanNBytes := func(data []byte, atEOF bool) (int, []byte, error) {
		if len(data) < int(n) {
			return 0, nil, nil
		} else {
			return int(n), data[:n], nil
		}
	}

	scanner := bufio.NewScanner(reader)
	scanner.Split(scanNBytes)

	table := make(map[string]float32)
	var total float32

	for scanner.Scan() {
		token, _ := hex.Encode(scanner.Bytes())
		table[token]++
		total++
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	for k, v := range table {
		table[k] = v / total
	}

	return &Table{Data:table}, nil
}

func (t *Table) Compare(u *Table) float32 {
	seen := make(map[string]bool)

	var diff float64

	for k := range t.Data {
		diff += math.Abs(float64(t.Data[k]) - float64(u.Data[k]))
		seen[k] = true
	}

	for k := range u.Data {
		if seen[k] {
			continue
		}
		diff += math.Abs(float64(t.Data[k]) - float64(u.Data[k]))
	}

	return float32(diff)
}
