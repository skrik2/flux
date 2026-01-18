package varint

import (
	"bytes"
	"testing"
)

// go test -bench=. -run=^$

var sinkU64 uint64
var sinkInt int

// -------------------------
// Test values (cover all lengths)
// -------------------------

var testValues = []uint64{
	0,
	63,
	64,
	16383,
	16384,
	1073741823,
	1073741824,
	Max,
}

// -------------------------
// Len
// -------------------------

func BenchmarkLen(b *testing.B) {
	for _, v := range testValues {
		b.Run("v="+itoa(v), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sinkInt = Len(v)
			}
		})
	}
}

// -------------------------
// Append
// -------------------------

func BenchmarkAppend(b *testing.B) {
	for _, v := range testValues {
		b.Run("v="+itoa(v), func(b *testing.B) {
			b.ReportAllocs()
			dst := make([]byte, 0, 8)
			for i := 0; i < b.N; i++ {
				dst = dst[:0]
				dst = Append(dst, v)
				sinkInt = len(dst)
			}
		})
	}
}

// -------------------------
// Parse
// -------------------------

func BenchmarkParse(b *testing.B) {
	for _, v := range testValues {
		buf := Append(nil, v)
		b.Run("v="+itoa(v), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var err error
				sinkU64, _, err = Parse(buf)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// -------------------------
// Peek
// -------------------------

func BenchmarkPeek(b *testing.B) {
	for _, v := range testValues {
		buf := Append(nil, v)
		b.Run("v="+itoa(v), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var err error
				sinkU64, err = Peek(buf)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// -------------------------
// Read (io.Reader)
// -------------------------

func BenchmarkRead(b *testing.B) {
	for _, v := range testValues {
		data := Append(nil, v)
		// 预先准备一个包含大量重复数据的 buffer，减少 Reset 开销
		multiData := bytes.Repeat(data, 100)
		br := bytes.NewReader(multiData)

		b.Run("v="+itoa(v), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer() // 重置计时器，排除准备数据的干扰
			for i := 0; i < b.N; i++ {
				// 如果读完了，重置指针
				if br.Len() < 8 {
					br.Reset(multiData)
				}

				var err error
				sinkU64, err = Read(br) // bytes.Reader 直接支持 ReadByte
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// -------------------------
// Write (io.Writer)
// -------------------------

type discardByteWriter struct{}

func (discardByteWriter) WriteByte(c byte) error { return nil }

func BenchmarkWrite(b *testing.B) {
	var buf bytes.Buffer
	for _, v := range testValues {
		b.Run("v="+itoa(v), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				buf.Reset()
				err := Write(&buf, v)
				if err != nil {
					b.Fatal(err)
				}
			}
			sinkInt = buf.Len()
		})
	}
}

// -------------------------
// Helpers
// -------------------------

func itoa(v uint64) string {
	switch v {
	case 0:
		return "0"
	case 63:
		return "63"
	case 64:
		return "64"
	case 16383:
		return "16383"
	case 16384:
		return "16384"
	case 1073741823:
		return "2^30-1"
	case 1073741824:
		return "2^30"
	case Max:
		return "Max"
	default:
		return "x"
	}
}
