// Package pbzx reads and writes the pbz* block-compression containers Apple
// wraps around payloads: pkgbuild's pbzx (xz) for --compression latest,
// and the siblings libParallelCompression and the aa tool produce.
//
// Layout, integers big-endian:
//
//	magic      4  "pbz" + an algorithm letter
//	blockSize  8  the writer's block size
//	chunks, until end of input:
//	  inflated 8  size of the chunk once decoded
//	  deflated 8  size of the chunk as stored
//	  data     deflated bytes: compressed, or the plain bytes when the
//	           chunk did not shrink (deflated == inflated)
//
// There is no trailer. Algorithms: 'x' xz (LZMA2), 'e' LZFSE, '4' LZ4 in
// Apple's bv4* framing, 'z' zlib, 'b' LZBITMAP (see pkg/lzbitmap).
// What pkgbuild writes, from its own output: 16 MiB blocks, one
// xz stream per chunk with no integrity check and an 8 MiB dictionary.
// The same rules hold for every variant; pkgbuild has used only pbzx for
// --compression latest on every --min-os-version from 12.0 to 26.0.
package pbzx

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-macos-pkg/pkg/lzbitmap"
	"github.com/go-compressions/lzfse"
	"github.com/ulikunitz/xz"
)

// Algorithm is the letter after "pbz" in the magic.
type Algorithm byte

// Algorithms.
const (
	XZ       Algorithm = 'x'
	LZFSE    Algorithm = 'e'
	LZ4      Algorithm = '4'
	Zlib     Algorithm = 'z'
	LZBitmap Algorithm = 'b'
)

func (a Algorithm) String() string {
	switch a {
	case XZ:
		return "xz"
	case LZFSE:
		return "lzfse"
	case LZ4:
		return "lz4"
	case Zlib:
		return "zlib"
	case LZBitmap:
		return "lzbitmap"
	}
	return fmt.Sprintf("unknown(%q)", byte(a))
}

// Magic returns the four-byte container magic for the algorithm.
func (a Algorithm) Magic() []byte { return []byte{'p', 'b', 'z', byte(a)} }

// DefaultBlockSize is what pkgbuild uses.
const DefaultBlockSize = 16 << 20

// maxBufferedChunk bounds chunks for the algorithms decoded in memory.
const maxBufferedChunk = 1 << 30

// Errors.
var (
	ErrNotPBZ               = errors.New("pbzx: not a pbz* container")
	ErrUnsupportedAlgorithm = errors.New("pbzx: unsupported algorithm")
)

// Magic is the pbzx magic, kept for callers that only know that variant.
var Magic = []byte("pbzx")

var xzMagic = []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}

// Sniff reports the algorithm of a pbz* header and whether head is one.
func Sniff(head []byte) (Algorithm, bool) {
	if len(head) < 4 || head[0] != 'p' || head[1] != 'b' || head[2] != 'z' {
		return 0, false
	}
	switch Algorithm(head[3]) {
	case XZ, LZFSE, LZ4, Zlib, LZBitmap:
		return Algorithm(head[3]), true
	}
	return 0, false
}

// IsPBZX reports whether head begins with any pbz* magic.
func IsPBZX(head []byte) bool {
	_, ok := Sniff(head)
	return ok
}

// Reader decodes a pbz* stream chunk by chunk.
type Reader struct {
	r         io.Reader
	algo      Algorithm
	blockSize uint64
	chunk     *chunkReader
	err       error
	parallel  *concurrentReader
}

// NewReader validates the header and returns a streaming decoder.
func NewReader(r io.Reader) (*Reader, error) {
	var hdr [12]byte
	if _, err := io.ReadFull(r, hdr[:4]); err != nil {
		return nil, ErrNotPBZ
	}
	algo, ok := Sniff(hdr[:4])
	if !ok {
		return nil, ErrNotPBZ
	}
	if _, err := io.ReadFull(r, hdr[4:]); err != nil {
		return nil, fmt.Errorf("pbzx: unable to read header: %w", err)
	}
	return &Reader{r: r, algo: algo, blockSize: binary.BigEndian.Uint64(hdr[4:12])}, nil
}

// Algorithm returns the container's compression algorithm.
func (pr *Reader) Algorithm() Algorithm { return pr.algo }

// BlockSize returns the block size the writer used.
func (pr *Reader) BlockSize() uint64 { return pr.blockSize }

// Flags is the old name of BlockSize.
//
// Deprecated: use BlockSize.
func (pr *Reader) Flags() uint64 { return pr.blockSize }

// Read decodes into p.
func (pr *Reader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if pr.parallel != nil {
		return pr.parallel.Read(p)
	}
	for {
		if pr.err != nil {
			return 0, pr.err
		}
		if pr.chunk == nil {
			header, err := readChunkHeader(pr.r)
			if err == nil {
				pr.chunk, err = newChunkReader(pr.algo, pr.r, header)
			}
			if err != nil {
				pr.err = err
				return 0, err
			}
		}
		n, err := pr.chunk.Read(p)
		if err == io.EOF {
			pr.chunk = nil
			if n == 0 {
				continue
			}
			return n, nil
		}
		if err != nil {
			pr.err = err
		}
		return n, err
	}
}

// Close stops concurrent decoding and waits for workers to finish. It does not
// close the input. The caller must interrupt any blocked input Read before Close,
// for example by closing its pipe. Close may run concurrently with Read on a
// reader returned by NewConcurrentReader.
func (pr *Reader) Close() error {
	if pr.parallel != nil {
		pr.parallel.cancel()
		pr.parallel.workers.Wait()
		return nil
	}
	if pr.chunk != nil {
		return pr.chunk.Close()
	}
	return nil
}

type chunkHeader struct {
	inflated, deflated uint64
}

func readChunkHeader(r io.Reader) (chunkHeader, error) {
	var hdr [16]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if err == io.EOF {
			return chunkHeader{}, io.EOF
		}
		return chunkHeader{}, fmt.Errorf("pbzx: unable to read chunk header: %w", err)
	}
	h := chunkHeader{binary.BigEndian.Uint64(hdr[:8]), binary.BigEndian.Uint64(hdr[8:])}
	if h.inflated > 1<<40 || h.deflated > 1<<40 {
		return h, fmt.Errorf("pbzx: implausible chunk sizes (%d, %d)", h.inflated, h.deflated)
	}
	if h.deflated > h.inflated {
		return h, fmt.Errorf("pbzx: chunk grew (%d stored for %d decoded)", h.deflated, h.inflated)
	}
	return h, nil
}

type chunkReader struct {
	decoded io.Reader
	stored  *io.LimitedReader
	buffer  *bufio.Reader
	left    int64
}

func newChunkReader(algo Algorithm, source io.Reader, header chunkHeader) (*chunkReader, error) {
	inflated, deflated := header.inflated, header.deflated
	stored := &io.LimitedReader{R: source, N: int64(deflated)}
	chunk := &chunkReader{stored: stored, left: int64(inflated)}
	// A chunk that did not compress is stored as is, and its sizes agree.
	if inflated == deflated {
		chunk.decoded = stored
		return chunk, nil
	}
	switch algo {
	case XZ:
		chunk.buffer = bufio.NewReader(stored)
		if head, err := chunk.buffer.Peek(6); err == nil && !bytes.Equal(head, xzMagic) {
			return nil, fmt.Errorf("pbzx: chunk is not an xz stream")
		}
		xr, err := xz.NewReader(chunk.buffer)
		if err != nil {
			return nil, fmt.Errorf("pbzx: bad xz chunk: %w", err)
		}
		chunk.decoded = xr
	case Zlib:
		// Supplying ReadByte prevents zlib from consuming trailing bytes
		// beyond its stream without leaving them available for validation.
		chunk.buffer = bufio.NewReader(stored)
		zr, err := zlib.NewReader(chunk.buffer)
		if err != nil {
			return nil, fmt.Errorf("pbzx: bad zlib chunk: %w", err)
		}
		chunk.decoded = zr
	case LZFSE, LZ4, LZBitmap:
		if inflated > maxBufferedChunk {
			return nil, fmt.Errorf("pbzx: %s chunk of %d bytes exceeds the %d-byte limit", algo, inflated, maxBufferedChunk)
		}
		data, err := io.ReadAll(stored)
		if err != nil {
			return nil, fmt.Errorf("pbzx: unable to read chunk: %w", err)
		}
		if stored.N != 0 {
			return nil, fmt.Errorf("pbzx: truncated chunk: %w", io.ErrUnexpectedEOF)
		}
		var out []byte
		switch algo {
		case LZFSE:
			out, err = lzfse.Decompress(data)
		case LZBitmap:
			out, err = lzbitmap.Decompress(data)
		default:
			out, err = decodeLZ4Frames(data, int(inflated))
		}
		if err != nil {
			return nil, fmt.Errorf("pbzx: bad %s chunk: %w", algo, err)
		}
		if uint64(len(out)) != inflated {
			return nil, fmt.Errorf("pbzx: %s chunk decoded to %d bytes, header says %d", algo, len(out), inflated)
		}
		chunk.decoded = bytes.NewReader(out)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, algo)
	}
	return chunk, nil
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, err := c.decoded.Read(p[:min(int64(len(p)), c.left)])
	c.left -= int64(n)
	if err != nil && err != io.EOF {
		return n, err
	}
	if c.left != 0 {
		if err == io.EOF {
			return n, fmt.Errorf("pbzx: chunk decoded short by %d bytes: %w", c.left, io.ErrUnexpectedEOF)
		}
		return n, nil
	}
	// Reaching the declared size is not EOF: read the decoder through its
	// trailer to validate checksums and reject an oversized expansion.
	var extra [1]byte
	if _, err := io.ReadFull(c.decoded, extra[:]); err != io.EOF {
		if err != nil {
			return n, err
		}
		return n, fmt.Errorf("pbzx: chunk decoded beyond its declared size")
	}
	if c.stored.N != 0 || c.buffer != nil && c.buffer.Buffered() != 0 {
		return n, fmt.Errorf("pbzx: trailing or truncated chunk data")
	}
	if err := c.Close(); err != nil {
		return n, err
	}
	return n, io.EOF
}

func (c *chunkReader) Close() error {
	if closer, ok := c.decoded.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// Writer encodes a pbz* stream.
type Writer struct {
	w         io.Writer
	algo      Algorithm
	blockSize int
	buf       []byte
	started   bool
	closed    bool
}

// NewWriter returns a Writer producing the container for algo with the
// given block size (0 selects pkgbuild's 16 MiB).
func NewWriter(w io.Writer, algo Algorithm, blockSize uint64) (*Writer, error) {
	switch algo {
	case XZ, LZFSE, LZ4, Zlib, LZBitmap:
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, byte(algo))
	}
	if blockSize == 0 {
		blockSize = DefaultBlockSize
	}
	if blockSize > maxBufferedChunk {
		return nil, fmt.Errorf("pbzx: block size %d exceeds the %d-byte limit", blockSize, maxBufferedChunk)
	}
	return &Writer{w: w, algo: algo, blockSize: int(blockSize), buf: make([]byte, 0, blockSize)}, nil
}

func (pw *Writer) header() error {
	if pw.started {
		return nil
	}
	pw.started = true
	hdr := make([]byte, 12)
	copy(hdr, pw.algo.Magic())
	binary.BigEndian.PutUint64(hdr[4:], uint64(pw.blockSize))
	_, err := pw.w.Write(hdr)
	return err
}

// Write buffers p, emitting a chunk whenever a full block is available.
func (pw *Writer) Write(p []byte) (int, error) {
	if pw.closed {
		return 0, errors.New("pbzx: write after close")
	}
	if err := pw.header(); err != nil {
		return 0, err
	}
	written := 0
	for len(p) > 0 {
		room := pw.blockSize - len(pw.buf)
		n := min(room, len(p))
		pw.buf = append(pw.buf, p[:n]...)
		p = p[n:]
		written += n
		if len(pw.buf) == pw.blockSize {
			if err := pw.flush(); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

// flush compresses and writes the buffered block.
func (pw *Writer) flush() error {
	if len(pw.buf) == 0 {
		return nil
	}
	compressed, err := compressChunk(pw.algo, pw.buf)
	if err != nil {
		return err
	}
	data := compressed
	if len(compressed) >= len(pw.buf) {
		data = pw.buf // incompressible: stored, sizes equal
	}
	var hdr [16]byte
	binary.BigEndian.PutUint64(hdr[0:8], uint64(len(pw.buf)))
	binary.BigEndian.PutUint64(hdr[8:16], uint64(len(data)))
	if _, err := pw.w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := pw.w.Write(data); err != nil {
		return err
	}
	pw.buf = pw.buf[:0]
	return nil
}

// Close writes the final, possibly short, chunk. An empty input still
// gets a header.
func (pw *Writer) Close() error {
	if pw.closed {
		return nil
	}
	pw.closed = true
	if err := pw.header(); err != nil {
		return err
	}
	return pw.flush()
}

// compressChunk compresses one block with the algorithm's Apple-matching
// parameters.
func compressChunk(algo Algorithm, block []byte) ([]byte, error) {
	var out bytes.Buffer
	switch algo {
	case XZ:
		// One xz stream per chunk, no integrity check, 8 MiB LZMA2
		// dictionary: what pkgbuild writes (stream flags 0x0000, LZMA2
		// property 0x16), the equivalent of xz -6.
		cfg := xz.WriterConfig{DictCap: 8 << 20, NoCheckSum: true}
		zw, err := cfg.NewWriter(&out)
		if err != nil {
			return nil, err
		}
		if _, err := zw.Write(block); err != nil {
			return nil, err
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
	case Zlib:
		zw := zlib.NewWriter(&out)
		if _, err := zw.Write(block); err != nil {
			return nil, err
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
	case LZFSE:
		data, err := lzfse.Compress(block)
		if err != nil {
			return nil, err
		}
		return data, nil
	case LZ4:
		return encodeLZ4Frames(block), nil
	case LZBitmap:
		return lzbitmap.Compress(block)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, algo)
	}
	return out.Bytes(), nil
}
