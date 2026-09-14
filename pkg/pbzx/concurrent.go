package pbzx

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
)

// NewConcurrentReader validates the header and decodes up to workers chunks in
// parallel, emitting bytes and errors in source order. Workers must be positive.
// Each chunk must fit the declared block size, up to the same 1 GiB buffering
// limit used by NewWriter. Unread results retain their worker slot, bounding
// read-ahead independently of the total payload size. The caller chooses the
// worker count to fit its CPU and memory budget.
//
// The caller owns r and must unblock any pending Read on cancellation or before
// calling Close. Call Close when finished, including after an early read failure.
func NewConcurrentReader(ctx context.Context, r io.Reader, workers int) (*Reader, error) {
	if workers < 1 {
		return nil, fmt.Errorf("pbzx: concurrent workers must be positive")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pr, err := NewReader(r)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	if pr.blockSize == 0 || pr.blockSize > maxBufferedChunk {
		return nil, fmt.Errorf("pbzx: concurrent block size must be between 1 and %d", maxBufferedChunk)
	}
	pr.parallel = newConcurrentReader(ctx, r, pr.blockSize, workers, func(chunk *concurrentChunk) error {
		return chunk.decode(pr.algo)
	})
	return pr, nil
}

type concurrentChunk struct {
	header   chunkHeader
	src, dst []byte
	ready    chan struct{}
	err      error
}

type concurrentReader struct {
	ctx     context.Context
	cancel  context.CancelFunc
	workers sync.WaitGroup
	free    chan *concurrentChunk
	pending chan *concurrentChunk
	current *concurrentChunk
	offset  int
	err     error
}

func newConcurrentReader(ctx context.Context, source io.Reader, blockSize uint64, workers int, decode func(*concurrentChunk) error) *concurrentReader {
	ctx, cancel := context.WithCancel(ctx)
	r := &concurrentReader{
		ctx: ctx, cancel: cancel,
		free: make(chan *concurrentChunk, workers), pending: make(chan *concurrentChunk, workers),
	}
	jobs := make(chan *concurrentChunk)
	for range workers {
		r.free <- &concurrentChunk{}
	}
	r.workers.Add(workers + 1)
	go r.parse(source, blockSize, jobs)
	for range workers {
		go r.decode(jobs, decode)
	}
	return r
}

func (r *concurrentReader) parse(source io.Reader, blockSize uint64, jobs chan<- *concurrentChunk) {
	defer r.workers.Done()
	defer close(r.pending)
	defer close(jobs)
	for {
		var chunk *concurrentChunk
		select {
		case <-r.ctx.Done():
			return
		case chunk = <-r.free:
		}
		chunk.ready = make(chan struct{})
		chunk.header, chunk.err = readChunkHeader(source)
		if chunk.err == io.EOF {
			return
		}
		if chunk.err == nil {
			// The shared header validation establishes deflated <= inflated.
			// Enforce the buffering bound before allocating either buffer.
			if chunk.header.inflated > blockSize {
				chunk.err = fmt.Errorf("pbzx: chunk exceeds concurrent block size %d", blockSize)
			} else {
				size := int(chunk.header.deflated)
				if cap(chunk.src) < size {
					chunk.src = make([]byte, size)
				}
				chunk.src = chunk.src[:size]
				if _, err := io.ReadFull(source, chunk.src); err != nil {
					chunk.err = fmt.Errorf("pbzx: unable to read chunk: %w", err)
				}
			}
		}
		select {
		case <-r.ctx.Done():
			return
		case r.pending <- chunk:
		}
		if chunk.err != nil {
			close(chunk.ready)
			return
		}
		select {
		case <-r.ctx.Done():
			return
		case jobs <- chunk:
		}
	}
}

func (r *concurrentReader) decode(jobs <-chan *concurrentChunk, decode func(*concurrentChunk) error) {
	defer r.workers.Done()
	for {
		select {
		case <-r.ctx.Done():
			return
		case chunk, ok := <-jobs:
			if !ok || r.ctx.Err() != nil {
				return
			}
			chunk.err = decode(chunk)
			close(chunk.ready)
		}
	}
}

func (c *concurrentChunk) decode(algo Algorithm) error {
	r, err := newChunkReader(algo, bytes.NewReader(c.src), c.header)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	size := int(c.header.inflated)
	if cap(c.dst) < size {
		c.dst = make([]byte, size)
	}
	c.dst = c.dst[:size]
	for n := 0; n < size; {
		read, err := r.Read(c.dst[n:])
		n += read
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
	// Empty chunks still need the shared end-of-chunk validation.
	if size == 0 {
		var extra [1]byte
		if _, err := r.Read(extra[:]); err != io.EOF {
			return err
		}
	}
	return nil
}

func (r *concurrentReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if r.err != nil {
			return 0, r.err
		}
		if err := r.ctx.Err(); err != nil {
			return r.fail(err)
		}
		if r.current != nil {
			if r.offset < len(r.current.dst) {
				n := copy(p, r.current.dst[r.offset:])
				r.offset += n
				return n, nil
			}
			r.free <- r.current
			r.current = nil
		}
		var chunk *concurrentChunk
		select {
		case <-r.ctx.Done():
			return r.fail(r.ctx.Err())
		case chunk = <-r.pending:
		}
		if chunk == nil {
			if err := r.ctx.Err(); err != nil {
				return r.fail(err)
			}
			r.err = io.EOF
			return 0, io.EOF
		}
		// Later failures must not prevent earlier chunks from reporting their
		// own bytes or error. Cancel remaining work only on an ordered error.
		select {
		case <-r.ctx.Done():
			return r.fail(r.ctx.Err())
		case <-chunk.ready:
		}
		if err := r.ctx.Err(); err != nil {
			return r.fail(err)
		}
		if chunk.err != nil {
			return r.fail(chunk.err)
		}
		r.current, r.offset = chunk, 0
	}
}

func (r *concurrentReader) fail(err error) (int, error) {
	r.err = err
	r.cancel()
	return 0, err
}
