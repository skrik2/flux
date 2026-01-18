package varint

import (
	"fmt"
	"io"
)

const (
	// Min is the minimum value allowed for a varint encoding
	Min uint64 = 0

	// Max is the maximum allowed value for a varint encoding (2^62 - 1)
	Max uint64 = 0x3FFFFFFFFFFFFFFF
)

// Internal maximums for each encoding length
const (
	_maxVarInt1 = 0x3F       // <=> 2^6-1  <=> 63
	_maxVarInt2 = 0x3FFF     // <=> 2^14-1 <=> 16383
	_maxVarInt4 = 0x3FFFFFFF // <=> 2^30-1 <=> 1073741823
	_maxVarInt8 = Max        // <=> 2^62-1 <=> 4611686018427387903
)

type varintLengthError struct {
	Num uint64
}

func (e *varintLengthError) Error() string {
	return fmt.Sprintf("value too big to fit in 62 bits: %d", e.Num)
}

// Len returns the number of bytes needed to encode v as a varint
func Len(v uint64) int {
	switch {
	case v>>6 == 0:
		return 1
	case v>>14 == 0:
		return 2
	case v>>30 == 0:
		return 4
	case v>>62 == 0:
		return 8
	default:
		panic(&varintLengthError{Num: v})
	}
}

// Append encodes v and appends it to dst, returning the new slice
func Append(dst []byte, v uint64) []byte {
	switch {
	case v <= _maxVarInt1:
		return append(dst, byte(v))
	case v <= _maxVarInt2:
		return append(dst,
			byte((v>>8)&0x3F)|0x40,
			byte(v),
		)
	case v <= _maxVarInt4:
		return append(dst,
			byte((v>>24)&0x3F)|0x80,
			byte(v>>16),
			byte(v>>8),
			byte(v),
		)
	case v <= _maxVarInt8:
		return append(dst,
			byte((v>>56)&0x3F)|0xC0,
			byte(v>>48),
			byte(v>>40),
			byte(v>>32),
			byte(v>>24),
			byte(v>>16),
			byte(v>>8),
			byte(v),
		)
	default:
		panic(&varintLengthError{Num: v})
	}
}

// Parse reads a varint from b and returns value, bytes consumed, and error
func Parse(b []byte) (value uint64, consumed int, err error) {
	if len(b) == 0 {
		return 0, 0, io.EOF
	}
	first := b[0]
	length := 1 << (first >> 6)
	if len(b) < length {
		return 0, 0, io.ErrUnexpectedEOF
	}

	value = uint64(first & 0x3f)
	for i := 1; i < length; i++ {
		value = (value << 8) | uint64(b[i])
	}
	return value, length, nil
}

// Peek reads a varint from b without consuming bytes
func Peek(b []byte) (uint64, error) {
	v, _, err := Parse(b)
	return v, err
}

// Read reads a varint from r (io.ByteReader)
func Read(r io.ByteReader) (uint64, error) {
	b0, err := r.ReadByte()
	if err != nil {
		return 0, err
	}

	switch b0 >> 6 {
	case 0: // 1 byte
		return uint64(b0 & 0x3F), nil
	case 1: // 2 bytes
		b1, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		return uint64(b0&0x3F)<<8 | uint64(b1), nil
	case 2: // 4 bytes
		b1, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		b2, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		b3, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		return (uint64(b0&0x3F) << 24) |
			(uint64(b1) << 16) |
			(uint64(b2) << 8) |
			uint64(b3), nil
	case 3: // 8 bytes
		b1, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		b2, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		b3, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		b4, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		b5, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		b6, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		b7, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		return (uint64(b0&0x3F) << 56) |
			(uint64(b1) << 48) |
			(uint64(b2) << 40) |
			(uint64(b3) << 32) |
			(uint64(b4) << 24) |
			(uint64(b5) << 16) |
			(uint64(b6) << 8) |
			uint64(b7), nil
	default:
		panic("unreachable")
	}
}

// Write encodes v and writes it to w (io.ByteWriter)
func Write(w io.ByteWriter, v uint64) error {
	switch {
	case v <= _maxVarInt1:
		return w.WriteByte(byte(v))
	case v <= _maxVarInt2:
		if err := w.WriteByte(byte((v>>8)&0x3F) | 0x40); err != nil {
			return err
		}
		return w.WriteByte(byte(v))
	case v <= _maxVarInt4:
		if err := w.WriteByte(byte((v>>24)&0x3F) | 0x80); err != nil {
			return err
		}
		if err := w.WriteByte(byte(v >> 16)); err != nil {
			return err
		}
		if err := w.WriteByte(byte(v >> 8)); err != nil {
			return err
		}
		return w.WriteByte(byte(v))
	case v <= _maxVarInt8:
		if err := w.WriteByte(byte((v>>56)&0x3F) | 0xC0); err != nil {
			return err
		}
		if err := w.WriteByte(byte(v >> 48)); err != nil {
			return err
		}
		if err := w.WriteByte(byte(v >> 40)); err != nil {
			return err
		}
		if err := w.WriteByte(byte(v >> 32)); err != nil {
			return err
		}
		if err := w.WriteByte(byte(v >> 24)); err != nil {
			return err
		}
		if err := w.WriteByte(byte(v >> 16)); err != nil {
			return err
		}
		if err := w.WriteByte(byte(v >> 8)); err != nil {
			return err
		}
		return w.WriteByte(byte(v))
	default:
		panic(&varintLengthError{Num: v})
	}
}
