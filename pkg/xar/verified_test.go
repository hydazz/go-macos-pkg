package xar

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"testing"
)

func verifiedFixture(t *testing.T, encoding string, padding bool) (*Reader, []byte) {
	t.Helper()
	plain := bytes.Repeat([]byte("verified streaming data\n"), 500)
	stored := plain
	if encoding != EncodingNone {
		var compressed bytes.Buffer
		var writer io.WriteCloser
		if encoding == "gzip bytes" {
			writer = gzip.NewWriter(&compressed)
			encoding = EncodingGzip
		} else {
			writer = zlib.NewWriter(&compressed)
		}
		if _, err := writer.Write(plain); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		stored = compressed.Bytes()
	}
	if padding {
		stored = append(bytes.Clone(stored), make([]byte, 32)...)
	}
	toc := fmt.Sprintf(`<xar><toc><checksum style="sha256"><offset>0</offset><size>32</size></checksum><file id="1"><name>Payload</name><type>file</type><data><offset>32</offset><size>%d</size><length>%d</length><encoding style="%s"/><archived-checksum style="sha256">%x</archived-checksum><extracted-checksum style="sha256">%x</extracted-checksum></data></file></toc></xar>`, len(plain), len(stored), encoding, sha256.Sum256(stored), sha256.Sum256(plain))
	archive := buildArchive(t, toc, ChecksumSHA256, stored)
	x, err := Open(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	return x, plain
}

func TestOpenVerified(t *testing.T) {
	for _, encoding := range []string{EncodingNone, EncodingGzip, "gzip bytes"} {
		t.Run(encoding, func(t *testing.T) {
			x, want := verifiedFixture(t, encoding, false)
			r, err := x.OpenVerified(x.Lookup("Payload"))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			got, err := io.ReadAll(r)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("content: %d bytes, %v", len(got), err)
			}
		})
	}
	t.Run("stored padding", func(t *testing.T) {
		x, want := verifiedFixture(t, EncodingGzip, true)
		r, err := x.OpenVerified(x.Lookup("Payload"))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		got, err := io.ReadAll(r)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("padded content: %d bytes, %v", len(got), err)
		}
	})
}

func TestOpenVerifiedRejectsInvalidData(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Data)
	}{
		{"archived checksum", func(d *Data) { d.ArchivedChecksum.Value = strings.Repeat("0", 64) }},
		{"extracted checksum", func(d *Data) { d.ExtractedChecksum.Value = strings.Repeat("0", 64) }},
		{"malformed checksum", func(d *Data) { d.ExtractedChecksum.Value = "oops" }},
		{"unknown checksum", func(d *Data) { d.ExtractedChecksum.Style = "unknown" }},
		{"short decoded data", func(d *Data) { d.Size++ }},
		{"oversized decoded data", func(d *Data) { d.Size-- }},
		{"negative decoded size", func(d *Data) { d.Size = -1 }},
		{"truncated stream trailer", func(d *Data) { d.Length--; d.ArchivedChecksum = nil }},
		{"range outside heap", func(d *Data) { d.Offset++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			x, _ := verifiedFixture(t, EncodingGzip, false)
			file := x.Lookup("Payload")
			test.mutate(file.Data)
			r, err := x.OpenVerified(file)
			if err == nil {
				_, err = io.Copy(io.Discard, r)
				r.Close()
			}
			if err == nil {
				t.Fatal("invalid entry passed verification")
			}
		})
	}
}

func TestOpenVerifiedAllowsAbsentChecksums(t *testing.T) {
	x, want := verifiedFixture(t, EncodingNone, false)
	file := x.Lookup("Payload")
	file.Data.ArchivedChecksum, file.Data.ExtractedChecksum = nil, nil
	r, err := x.OpenVerified(file)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("unchecked content: %v", err)
	}
}

func TestOpenEAVerified(t *testing.T) {
	x, want := verifiedFixture(t, EncodingGzip, false)
	d := x.Lookup("Payload").Data
	ea := &EA{Name: "com.example.attribute", Offset: d.Offset, Length: d.Length, Size: d.Size,
		Encoding: d.Encoding, ArchivedChecksum: d.ArchivedChecksum, ExtractedChecksum: d.ExtractedChecksum}
	r, err := x.OpenEAVerified(ea)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("attribute content: %v", err)
	}
	ea.ExtractedChecksum.Value = strings.Repeat("0", 64)
	r, err = x.OpenEAVerified(ea)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := io.Copy(io.Discard, r); err == nil {
		t.Fatal("corrupt attribute verified")
	}
}

type countedReaderAt struct {
	io.ReaderAt
	read int
}

func (r *countedReaderAt) ReadAt(p []byte, offset int64) (int, error) {
	n, err := r.ReaderAt.ReadAt(p, offset)
	r.read += n
	return n, err
}

func TestOpenVerifiedReadsStoredBytesOnceAndCloseDoesNotDrain(t *testing.T) {
	for _, early := range []bool{false, true} {
		x, _ := verifiedFixture(t, EncodingNone, false)
		source := &countedReaderAt{ReaderAt: x.r}
		x.r = source
		file := x.Lookup("Payload")
		r, err := x.OpenVerified(file)
		if err != nil {
			t.Fatal(err)
		}
		if early {
			if _, err := io.ReadFull(r, make([]byte, 1)); err != nil {
				t.Fatal(err)
			}
		} else if _, err := io.Copy(io.Discard, r); err != nil {
			t.Fatal(err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		want := int(file.Data.Length)
		if early {
			want = 1
		}
		if source.read != want {
			t.Fatalf("read %d stored bytes, want %d", source.read, want)
		}
	}
}
