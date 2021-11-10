package common

import "io"

type BufferPrefixedReader struct {
	Reader io.Reader
	Buffer []byte

	ptr int
}

func (br *BufferPrefixedReader) Read(b []byte) (int, error) {
	if br.ptr >= len(br.Buffer) {
		return br.Reader.Read(b)
	}

	bf := br.Buffer[br.ptr:]
	lb := len(b)
	lbf := len(bf)
	if lb <= lbf {
		copy(b, bf)
		br.ptr += lb
		return lb, nil
	}

	copy(b, bf)
	n, err := br.Reader.Read(b[lbf:])
	if err != nil {
		return 0, err
	}
	br.ptr = len(br.Buffer)
	return n + lbf, nil
}
