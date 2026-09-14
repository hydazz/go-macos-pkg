package pbzx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

func readers() map[string]func(io.Reader) (*Reader, error) {
	return map[string]func(io.Reader) (*Reader, error){
		"sequential":   NewReader,
		"one worker":   func(r io.Reader) (*Reader, error) { return NewConcurrentReader(context.Background(), r, 1) },
		"four workers": func(r io.Reader) (*Reader, error) { return NewConcurrentReader(context.Background(), r, 4) },
	}
}

func TestConcurrentRoundTrips(t *testing.T) {
	data := bytes.Repeat([]byte("concurrent compression\x00"), 1200)
	for _, algo := range []Algorithm{XZ, Zlib, LZFSE, LZ4, LZBitmap} {
		var encoded bytes.Buffer
		w, err := NewWriter(&encoded, algo, 1024)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		for name, newReader := range readers() {
			t.Run(algo.String()+"/"+name, func(t *testing.T) {
				r, err := newReader(bytes.NewReader(encoded.Bytes()))
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				got, err := io.ReadAll(r)
				if err != nil || !bytes.Equal(got, data) {
					t.Fatalf("parity: %d bytes, %v", len(got), err)
				}
				if r.Algorithm() != algo || r.BlockSize() != 1024 {
					t.Fatal("lost container metadata")
				}
			})
		}
	}
}

func TestConcurrentMaximumChunks(t *testing.T) {
	data := bytes.Repeat([]byte("maximum block\x00"), DefaultBlockSize/14+1)[:DefaultBlockSize]
	stream := buildPBZX(t, [][]byte{data, data, []byte("raw tail")}, []bool{true, true, false})
	want := sha256.New()
	want.Write(data)
	want.Write(data)
	want.Write([]byte("raw tail"))
	for name, newReader := range readers() {
		t.Run(name, func(t *testing.T) {
			r, err := newReader(bytes.NewReader(stream))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			got := sha256.New()
			n, err := io.Copy(got, r)
			if err != nil || n != 2*DefaultBlockSize+8 || !bytes.Equal(got.Sum(nil), want.Sum(nil)) {
				t.Fatalf("parity: %d, %v", n, err)
			}
		})
	}
}

func TestReadersValidateCompleteChunks(t *testing.T) {
	data := bytes.Repeat([]byte("checksum and trailer\n"), 1024)
	xz := buildPBZX(t, [][]byte{data}, []bool{true})
	compressed := xz[28:]
	indexSize := (int(binary.LittleEndian.Uint32(compressed[len(compressed)-8:])) + 1) * 4
	checksum := len(xz) - 12 - indexSize - 8
	mutate := func(offset int) []byte { b := bytes.Clone(xz); b[offset] ^= 1; return b }
	trailing := append(bytes.Clone(xz), 'x')
	binary.BigEndian.PutUint64(trailing[20:], uint64(len(compressed)+1))
	oversized := bytes.Clone(xz)
	binary.BigEndian.PutUint64(oversized[12:], uint64(len(data)-1))
	short := bytes.Clone(xz)
	binary.BigEndian.PutUint64(short[12:], uint64(len(data)+1))
	truncated := bytes.Clone(xz[:len(xz)-1])
	binary.BigEndian.PutUint64(truncated[20:], uint64(len(compressed)-1))
	for name, input := range map[string][]byte{
		"checksum": mutate(checksum), "header CRC": mutate(36), "footer": mutate(len(xz) - 12),
		"truncated stored": xz[:len(xz)-1], "truncated XZ": truncated,
		"trailing XZ": trailing, "oversized output": oversized, "short output": short,
		"trailing PBZX": append(bytes.Clone(xz), 1),
	} {
		for mode, newReader := range readers() {
			t.Run(name+"/"+mode, func(t *testing.T) {
				r, err := newReader(bytes.NewReader(input))
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				if _, err := io.Copy(io.Discard, r); err == nil {
					t.Fatal("accepted corrupt chunk")
				}
			})
		}
	}
}

func fakeStream(count int) []byte {
	data := []byte("pbzx")
	data = binary.BigEndian.AppendUint64(data, 1024)
	for i := range count {
		data = binary.BigEndian.AppendUint64(data, 1024)
		data = binary.BigEndian.AppendUint64(data, 1)
		data = append(data, byte(i+1))
	}
	return data
}

func await[T any](t *testing.T, done <-chan T) T {
	t.Helper()
	select {
	case value := <-done:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("operation did not terminate")
		var zero T
		return zero
	}
}

func testReader(t *testing.T, ctx context.Context, source io.Reader, decode func(*concurrentChunk) error) *Reader {
	t.Helper()
	r := &Reader{parallel: newConcurrentReader(ctx, source, 1024, 4, decode)}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

type countingReader struct {
	io.Reader
	bytes atomic.Int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.bytes.Add(int64(n))
	return n, err
}

func TestConcurrentOrderingAndBackpressure(t *testing.T) {
	const count = 40
	started, finished := make(chan byte, count), make(chan byte, count)
	release := make([]chan struct{}, count)
	for i := range release {
		release[i] = make(chan struct{})
	}
	defer func() {
		for _, c := range release {
			select {
			case <-c:
			default:
				close(c)
			}
		}
	}()
	source := &countingReader{Reader: bytes.NewReader(fakeStream(count)[12:])}
	r := testReader(t, t.Context(), source, func(c *concurrentChunk) error {
		id := c.src[0]
		started <- id
		<-release[id-1]
		c.dst = bytes.Repeat([]byte{id}, 1024)
		finished <- id
		return nil
	})
	for range 4 {
		await(t, started)
	}
	for _, id := range []int{4, 3, 2, 1} {
		close(release[id-1])
		await(t, finished)
	}
	var b [1]byte
	if _, err := r.Read(b[:]); err != nil || b[0] != 1 {
		t.Fatalf("first byte %v, %v", b, err)
	}
	if got := source.bytes.Load(); got != 4*17 {
		t.Fatalf("read ahead %d bytes beyond four slots", got)
	}
	for _, c := range release[4:] {
		close(c)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{}
	for id := 1; id <= count; id++ {
		want = append(want, bytes.Repeat([]byte{byte(id)}, 1024)...)
	}
	if !bytes.Equal(got, want[1:]) {
		t.Fatal("chunks emitted out of order")
	}
}

func TestConcurrentErrorOrder(t *testing.T) {
	first, later := errors.New("first"), errors.New("later")
	laterDone := make(chan struct{})
	r := testReader(t, t.Context(), bytes.NewReader(fakeStream(2)[12:]), func(c *concurrentChunk) error {
		if c.src[0] == 1 {
			<-laterDone
			return first
		}
		close(laterDone)
		return later
	})
	for range 2 {
		if _, err := r.Read(make([]byte, 1)); !errors.Is(err, first) {
			t.Fatalf("error order: %v", err)
		}
	}
}

func TestConcurrentStopsWorkers(t *testing.T) {
	for _, earlyClose := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancellation", true: "early close"}[earlyClose], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			started := make(chan struct{}, 4)
			release := make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			var active atomic.Int32
			r := testReader(t, ctx, bytes.NewReader(fakeStream(20)[12:]), func(c *concurrentChunk) error {
				active.Add(1)
				defer active.Add(-1)
				started <- struct{}{}
				<-release
				c.dst = make([]byte, 1024)
				return nil
			})
			for range 4 {
				await(t, started)
			}
			readDone := make(chan error, 1)
			go func() { _, err := r.Read(make([]byte, 1)); readDone <- err }()
			closeDone := make(chan error, 1)
			go func() {
				if !earlyClose {
					cancel()
				}
				closeDone <- r.Close()
			}()
			await(t, r.parallel.ctx.Done())
			close(release)
			if err := await(t, closeDone); err != nil {
				t.Fatal(err)
			}
			if err := await(t, readDone); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel read: %v", err)
			}
			if active.Load() != 0 || len(started) != 0 {
				t.Fatal("workers survived close")
			}
		})
	}
}

func TestConcurrentErrorDoesNotWaitForSource(t *testing.T) {
	input, output := io.Pipe()
	defer output.Close()
	wrote := make(chan error, 1)
	go func() { _, err := output.Write(fakeStream(1)[12:]); wrote <- err }()
	want := errors.New("decode failed")
	r := testReader(t, t.Context(), input, func(*concurrentChunk) error { return want })
	defer input.Close()
	if err := await(t, wrote); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := r.Read(make([]byte, 1)); done <- err }()
	if err := await(t, done); !errors.Is(err, want) {
		t.Fatalf("ordered failure blocked behind source read: %v", err)
	}
	// The caller releases its source before joining the library's workers.
	input.Close()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentRejectsLengthsBeforeReadingBody(t *testing.T) {
	for _, sizes := range [][2]uint64{{DefaultBlockSize + 1, 1}, {1, 2}, {1, ^uint64(0)}, {^uint64(0), 1}} {
		input := fakeStream(1)[:28]
		binary.BigEndian.PutUint64(input[12:], sizes[0])
		binary.BigEndian.PutUint64(input[20:], sizes[1])
		source := &countingReader{Reader: bytes.NewReader(input)}
		r, err := NewConcurrentReader(t.Context(), source, 4)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, r); err == nil {
			t.Fatal("accepted invalid length")
		}
		r.Close()
		if source.bytes.Load() != 28 {
			t.Fatal("read oversized body")
		}
	}
}

func TestConcurrentRejectsHeaderAndWorkerBounds(t *testing.T) {
	for _, workers := range []int{-1, 0} {
		if _, err := NewConcurrentReader(t.Context(), bytes.NewReader(fakeStream(1)), workers); err == nil {
			t.Fatalf("accepted %d workers", workers)
		}
	}
	for _, data := range [][]byte{[]byte("pbzx"), make([]byte, 12), append([]byte("pbzx"), make([]byte, 8)...)} {
		if _, err := NewConcurrentReader(t.Context(), bytes.NewReader(data), 4); err == nil {
			t.Fatal("accepted header")
		}
	}
}

func TestReadersValidateZlibTrailer(t *testing.T) {
	var encoded bytes.Buffer
	w, err := NewWriter(&encoded, Zlib, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(bytes.Repeat([]byte{'z'}, 1024)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	corrupt := bytes.Clone(encoded.Bytes())
	corrupt[len(corrupt)-1] ^= 1
	trailing := append(bytes.Clone(encoded.Bytes()), 'x')
	binary.BigEndian.PutUint64(trailing[20:], uint64(len(trailing)-28))
	for name, data := range map[string][]byte{"checksum": corrupt, "trailing data": trailing} {
		for mode, newReader := range readers() {
			t.Run(name+"/"+mode, func(t *testing.T) {
				r, err := newReader(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				if _, err := io.Copy(io.Discard, r); err == nil {
					t.Fatal("accepted malformed zlib chunk")
				}
			})
		}
	}
}

func TestConcurrentCallerChoosesWorkerAndBlockSizes(t *testing.T) {
	input := fakeStream(0)
	binary.BigEndian.PutUint64(input[4:], 2*DefaultBlockSize)
	r, err := NewConcurrentReader(t.Context(), bytes.NewReader(input), 5)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := io.Copy(io.Discard, r); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint64(input[4:], maxBufferedChunk+1)
	if _, err := NewConcurrentReader(t.Context(), bytes.NewReader(input), 1); err == nil {
		t.Fatal("accepted an unbounded block size")
	}
}
