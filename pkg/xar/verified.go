package xar

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strings"
)

// OpenVerified returns decoded entry bytes, checking the declared lengths and
// any archived and extracted checksums as they are read. Read to EOF to complete
// verification. Close releases the decoder without draining unread input.
func (x *Reader) OpenVerified(f *File) (io.ReadCloser, error) {
	if f.Data == nil {
		return nil, fmt.Errorf("xar: %s has no data", f.Path())
	}
	return x.openVerified(f.Path(), f.Data)
}

// OpenEAVerified is OpenVerified for an extended attribute.
func (x *Reader) OpenEAVerified(ea *EA) (io.ReadCloser, error) {
	return x.openVerified(ea.Name, &Data{
		Offset: ea.Offset, Length: ea.Length, Size: ea.Size, Encoding: ea.Encoding,
		ArchivedChecksum: ea.ArchivedChecksum, ExtractedChecksum: ea.ExtractedChecksum,
	})
}

func (x *Reader) openVerified(name string, data *Data) (io.ReadCloser, error) {
	if data.Size < 0 {
		return nil, fmt.Errorf("xar: %s has a negative decoded size", name)
	}
	raw, err := x.heapSection(data.Offset, data.Length)
	if err != nil {
		return nil, err
	}
	archived, err := newDigestCheck(data.ArchivedChecksum)
	if err != nil {
		return nil, err
	}
	extracted, err := newDigestCheck(data.ExtractedChecksum)
	if err != nil {
		return nil, err
	}
	stored := io.TeeReader(raw, archived)
	decoded, err := decode(stored, data.Encoding.Style)
	if err != nil {
		return nil, err
	}
	return &verifiedReader{
		name: name, decoded: decoded, stored: stored, raw: raw, left: data.Size,
		archived: archived, extracted: extracted,
	}, nil
}

type digestCheck struct {
	hash hash.Hash
	want []byte
}

func newDigestCheck(d *Digest) (*digestCheck, error) {
	c := &digestCheck{}
	if d == nil || d.Value == "" {
		return c, nil
	}
	alg, err := ParseChecksumStyle(d.Style)
	if err != nil {
		return nil, err
	}
	c.hash, err = alg.New()
	if err != nil {
		return nil, err
	}
	c.want, err = hex.DecodeString(strings.TrimSpace(d.Value))
	if err != nil || len(c.want) != c.hash.Size() {
		return nil, fmt.Errorf("xar: malformed %s checksum", d.Style)
	}
	return c, nil
}

func (c *digestCheck) Write(p []byte) (int, error) {
	if c.hash != nil {
		return c.hash.Write(p)
	}
	return len(p), nil
}

func (c *digestCheck) valid() bool {
	return c.hash == nil || bytes.Equal(c.hash.Sum(nil), c.want)
}

type verifiedReader struct {
	name                string
	decoded             io.ReadCloser
	stored              io.Reader
	raw                 *io.SectionReader
	archived, extracted *digestCheck
	left                int64
	err                 error
}

func (r *verifiedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	n, err := r.decoded.Read(p[:min(int64(len(p)), r.left)])
	r.left -= int64(n)
	_, _ = r.extracted.Write(p[:n])
	switch {
	case err != nil && err != io.EOF:
	case r.left != 0 && err == io.EOF:
		err = fmt.Errorf("decoded data is short by %d bytes: %w", r.left, io.ErrUnexpectedEOF)
	case r.left != 0:
		return n, nil
	default:
		err = r.finish()
	}
	if err != nil && err != io.EOF {
		err = fmt.Errorf("xar: %s: %w", r.name, err)
	}
	r.err = err
	return n, err
}

func (r *verifiedReader) finish() error {
	var extra [1]byte
	if _, err := io.ReadFull(r.decoded, extra[:]); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("decoded data exceeds declared size")
	}
	// Padding belongs to the stored checksum, even when the decoder stops
	// before the end of its section. Bytes already buffered were hashed on read.
	if _, err := io.Copy(io.Discard, r.stored); err != nil {
		return err
	}
	position, err := r.raw.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if position != r.raw.Size() {
		return io.ErrUnexpectedEOF
	}
	if !r.archived.valid() {
		return fmt.Errorf("archived checksum mismatch")
	}
	if !r.extracted.valid() {
		return fmt.Errorf("extracted checksum mismatch")
	}
	return io.EOF
}

func (r *verifiedReader) Close() error { return r.decoded.Close() }
