// Reading xar archives: header, table of contents, heap access and
// per-entry decoding and verification.

package xar

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"compress/zlib"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

// maxTOCSize bounds the table of contents we are willing to decompress. A
// real package's TOC is kilobytes; 7-Zip draws the line at 1 GiB, and a
// smaller bound here keeps a corrupt header from allocating the moon.
const maxTOCSize = 256 << 20

// ErrUnsupportedEncoding reports a heap encoding this reader cannot decode.
var ErrUnsupportedEncoding = errors.New("xar: unsupported entry encoding")

// Reader reads a xar archive from an io.ReaderAt.
type Reader struct {
	r    io.ReaderAt
	size int64

	header        Header
	toc           *TOC
	rawTOC        []byte // uncompressed TOC XML, exactly as stored
	compressedTOC []byte
	heapOffset    int64
	storedDigest  []byte // the TOC digest as recorded in the heap

	files  []*File
	byPath map[string]*File
	byID   map[int]*File

	closer io.Closer
}

// Open reads the header and table of contents from r, which is size bytes
// long. The heap is not read until an entry is opened.
func Open(r io.ReaderAt, size int64) (*Reader, error) {
	hdr, err := ReadHeader(r)
	if err != nil {
		return nil, err
	}
	if hdr.TOCCompressed > maxTOCSize || hdr.TOCUncompressed > maxTOCSize {
		return nil, fmt.Errorf("xar: implausible table of contents size (%d compressed, %d uncompressed)", hdr.TOCCompressed, hdr.TOCUncompressed)
	}
	if int64(hdr.Size)+int64(hdr.TOCCompressed) > size {
		return nil, fmt.Errorf("xar: table of contents runs past the end of the file")
	}

	compressed := make([]byte, hdr.TOCCompressed)
	if _, err := r.ReadAt(compressed, int64(hdr.Size)); err != nil {
		return nil, fmt.Errorf("xar: unable to read table of contents: %w", err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("xar: table of contents is not zlib data: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(zr, int64(hdr.TOCUncompressed)+1))
	if err != nil {
		return nil, fmt.Errorf("xar: unable to decompress table of contents: %w", err)
	}
	// Both libarchive and 7-Zip treat a length disagreement as corruption,
	// and so do we: a TOC whose declared size is wrong was not written by a
	// working xar implementation, whatever else it says.
	if uint64(len(raw)) != hdr.TOCUncompressed {
		return nil, fmt.Errorf("xar: table of contents is %d bytes, header says %d", len(raw), hdr.TOCUncompressed)
	}

	toc, err := parseTOC(raw)
	if err != nil {
		return nil, err
	}

	x := &Reader{
		r:             r,
		size:          size,
		header:        *hdr,
		toc:           toc,
		rawTOC:        raw,
		compressedTOC: compressed,
		heapOffset:    hdr.HeapOffset(),
		byPath:        make(map[string]*File),
		byID:          make(map[int]*File),
	}

	// The TOC digest sits at the start of the heap. Its location is in the
	// TOC itself; trust it, but bound it, so a hostile TOC cannot make us
	// read arbitrary file ranges as a digest.
	if c := toc.Checksum; c != nil {
		heapSize := size - x.heapOffset
		if c.Size < 0 || c.Size > 128 || c.Offset < 0 || c.Offset > heapSize || c.Size > heapSize-c.Offset {
			return nil, fmt.Errorf("xar: table of contents checksum record is out of range")
		}
		x.storedDigest = make([]byte, c.Size)
		if _, err := r.ReadAt(x.storedDigest, x.heapOffset+c.Offset); err != nil {
			return nil, fmt.Errorf("xar: unable to read table of contents digest: %w", err)
		}
	}

	x.flatten(toc.Files, "")
	return x, nil
}

// OpenFile opens the archive at path. Close releases the file.
func OpenFile(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	x, err := Open(f, st.Size())
	if err != nil {
		f.Close()
		return nil, err
	}
	x.closer = f
	return x, nil
}

// Close releases the underlying file when the Reader opened it.
func (x *Reader) Close() error {
	if x.closer != nil {
		return x.closer.Close()
	}
	return nil
}

// flatten walks the entry tree depth-first, assigning paths.
func (x *Reader) flatten(files []*File, parent string) {
	for _, f := range files {
		name := f.Name()
		if parent == "" {
			f.path = name
		} else {
			f.path = parent + "/" + name
		}
		x.files = append(x.files, f)
		x.byPath[f.path] = f
		x.byID[f.ID] = f
		x.flatten(f.Children, f.path)
	}
}

// Header returns the parsed archive header.
func (x *Reader) Header() Header { return x.header }

// TOC returns the parsed table of contents.
func (x *Reader) TOC() *TOC { return x.toc }

// RawTOC returns the uncompressed table of contents XML exactly as stored.
func (x *Reader) RawTOC() []byte { return x.rawTOC }

// CompressedTOC returns the table of contents as stored, still compressed.
// This is what the TOC digest and the signatures are computed over.
func (x *Reader) CompressedTOC() []byte { return x.compressedTOC }

// HeapOffset returns the file offset of heap byte 0.
func (x *Reader) HeapOffset() int64 { return x.heapOffset }

// Size returns the size of the input as given to Open.
func (x *Reader) Size() int64 { return x.size }

// Files returns every entry in depth-first order, directories before their
// children, with paths resolved.
func (x *Reader) Files() []*File { return x.files }

// Lookup returns the entry at a slash-separated path, or nil.
func (x *Reader) Lookup(path string) *File {
	return x.byPath[strings.Trim(path, "/")]
}

// FileByID returns the entry with the given TOC id, or nil.
func (x *Reader) FileByID(id int) *File { return x.byID[id] }

// StoredTOCDigest returns the TOC digest recorded in the heap, or nil when
// the archive has none.
func (x *Reader) StoredTOCDigest() []byte { return x.storedDigest }

// ComputeTOCDigest digests the compressed table of contents with the
// header's algorithm. This is the value the stored digest, the RSA signature
// and the CMS signature all commit to.
func (x *Reader) ComputeTOCDigest() ([]byte, error) {
	h, err := x.header.ChecksumAlg.New()
	if err != nil {
		return nil, err
	}
	h.Write(x.compressedTOC)
	return h.Sum(nil), nil
}

// TOCDigestValid reports whether the stored digest matches the compressed
// TOC. An archive with no checksum is reported as invalid: the caller asked
// whether the TOC is protected, and it is not.
func (x *Reader) TOCDigestValid() bool {
	if x.storedDigest == nil {
		return false
	}
	want, err := x.ComputeTOCDigest()
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(want, x.storedDigest) == 1
}

// HeapEnd returns the file offset one past the last byte the table of
// contents accounts for. Bytes beyond it are not part of the archive; a
// notarization ticket lives there.
func (x *Reader) HeapEnd() int64 {
	end := x.heapOffset
	if c := x.toc.Checksum; c != nil {
		end = max(end, x.heapOffset+c.Offset+c.Size)
	}
	for _, s := range []*Signature{x.toc.Signature, x.toc.XSignature} {
		if s != nil {
			end = max(end, x.heapOffset+s.Offset+s.Size)
		}
	}
	for _, f := range x.files {
		if f.Data != nil {
			end = max(end, x.heapOffset+f.Data.Offset+f.Data.Length)
		}
		for _, ea := range f.EAs {
			end = max(end, x.heapOffset+ea.Offset+ea.Length)
		}
	}
	return end
}

// HeapSection returns a reader over a heap range, bounds-checked. Offsets
// are heap-relative, as in the table of contents.
func (x *Reader) HeapSection(offset, length int64) (*io.SectionReader, error) {
	return x.heapSection(offset, length)
}

// heapSection returns a reader over a heap range, bounds-checked.
//
// The bound is expressed by subtraction rather than by adding the two
// together. Both come from the table of contents, so both are chosen by
// whoever made the file, and heapOffset+offset+length overflows int64 for
// large values and wraps to a negative number that passes any upper-bound
// test. Open has already established that heapOffset is within the file,
// so heapSize below cannot be negative.
func (x *Reader) heapSection(offset, length int64) (*io.SectionReader, error) {
	heapSize := x.size - x.heapOffset
	if offset < 0 || length < 0 || offset > heapSize || length > heapSize-offset {
		return nil, fmt.Errorf("xar: entry data (offset %d, length %d) is outside the file", offset, length)
	}
	return io.NewSectionReader(x.r, x.heapOffset+offset, length), nil
}

// OpenRaw returns the entry's bytes exactly as stored in the heap, still
// encoded.
func (x *Reader) OpenRaw(f *File) (*io.SectionReader, error) {
	if f.Data == nil {
		return nil, fmt.Errorf("xar: %s has no data", f.Path())
	}
	return x.heapSection(f.Data.Offset, f.Data.Length)
}

// Open returns the entry's decoded bytes.
func (x *Reader) Open(f *File) (io.ReadCloser, error) {
	raw, err := x.OpenRaw(f)
	if err != nil {
		return nil, err
	}
	return decode(raw, f.Data.Encoding.Style)
}

// OpenEA returns an extended attribute's decoded bytes.
func (x *Reader) OpenEA(ea *EA) (io.ReadCloser, error) {
	raw, err := x.heapSection(ea.Offset, ea.Length)
	if err != nil {
		return nil, err
	}
	return decode(raw, ea.Encoding.Style)
}

// decode wraps stored bytes in the decoder their encoding style names.
func decode(raw io.Reader, style string) (io.ReadCloser, error) {
	switch strings.ToLower(strings.TrimSpace(style)) {
	case EncodingNone, "":
		return io.NopCloser(raw), nil
	case EncodingGzip, EncodingZlib:
		// The style says gzip; the bytes are zlib. Sniff anyway, because a
		// writer that took the name literally would produce real gzip and
		// there is no reason to refuse it.
		buffer := bufio.NewReader(raw)
		magic, err := buffer.Peek(2)
		if err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
			gz, err := gzip.NewReader(buffer)
			if err != nil {
				return nil, fmt.Errorf("xar: %w", err)
			}
			return gz, nil
		}
		zr, err := zlib.NewReader(buffer)
		if err != nil {
			return nil, fmt.Errorf("xar: %w", err)
		}
		return zr, nil
	case EncodingBzip2:
		return io.NopCloser(bzip2.NewReader(raw)), nil
	case EncodingXZ:
		xr, err := xz.NewReader(raw)
		if err != nil {
			return nil, fmt.Errorf("xar: %w", err)
		}
		return io.NopCloser(xr), nil
	case EncodingLZMA:
		lr, err := lzma.NewReader(raw)
		if err != nil {
			return nil, fmt.Errorf("xar: %w", err)
		}
		return io.NopCloser(lr), nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedEncoding, style)
	}
}

// Verify checks the entry's stored and decoded lengths and any checksums present.
// Entries without data verify trivially.
func (x *Reader) Verify(f *File) error {
	if f.Data == nil {
		return nil
	}
	r, err := x.OpenVerified(f)
	if err != nil {
		return err
	}
	defer r.Close()
	_, err = io.Copy(io.Discard, r)
	return err
}
