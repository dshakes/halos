package gateway

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

// EventStreamToSSE converts an AWS event stream (Bedrock
// invoke-with-response-stream) carrying Anthropic events into the SSE the
// Messages API streams: each chunk's {"bytes": base64(event json)} becomes
// "event: <type>\ndata: <json>\n\n". Exception frames become an SSE error event.
func EventStreamToSSE(rc io.ReadCloser) io.ReadCloser {
	return &sseReader{src: rc, br: bufio.NewReader(rc)}
}

type sseReader struct {
	src io.Closer
	br  *bufio.Reader
	buf bytes.Buffer
	err error
}

func (s *sseReader) Close() error { return s.src.Close() }

func (s *sseReader) Read(p []byte) (int, error) {
	for s.buf.Len() == 0 && s.err == nil {
		s.err = s.next()
	}
	if s.buf.Len() > 0 {
		return s.buf.Read(p)
	}
	return 0, s.err
}

// next decodes one frame into s.buf. Frame: total u32 | headers u32 | prelude
// crc u32 | headers | payload | message crc u32 (CRC-32 IEEE).
func (s *sseReader) next() error {
	var pre [12]byte
	if _, err := io.ReadFull(s.br, pre[:]); err != nil {
		return err // io.EOF between frames is a clean end
	}
	total, hlen := binary.BigEndian.Uint32(pre[0:4]), binary.BigEndian.Uint32(pre[4:8])
	if crc32.ChecksumIEEE(pre[:8]) != binary.BigEndian.Uint32(pre[8:12]) || total < 16 || hlen > total-16 || total > 16<<20 {
		return errors.New("gateway: corrupt event stream prelude")
	}
	rest := make([]byte, total-12)
	if _, err := io.ReadFull(s.br, rest); err != nil {
		return fmt.Errorf("gateway: truncated event stream frame: %w", err)
	}
	h := crc32.NewIEEE()
	h.Write(pre[:])
	h.Write(rest[:len(rest)-4])
	if h.Sum32() != binary.BigEndian.Uint32(rest[len(rest)-4:]) {
		return errors.New("gateway: event stream frame checksum mismatch")
	}
	hdrs, payload := rest[:hlen], rest[hlen:len(rest)-4]
	msgType, excType := "", ""
	for len(hdrs) > 0 {
		var name, val string
		var err error
		if name, val, hdrs, err = eventHeader(hdrs); err != nil {
			return err
		}
		switch name {
		case ":message-type":
			msgType = val
		case ":exception-type":
			excType = val
		}
	}
	if msgType == "exception" || msgType == "error" {
		b, _ := json.Marshal(map[string]any{"type": "error", "error": map[string]string{"type": excType, "message": string(payload)}})
		fmt.Fprintf(&s.buf, "event: error\ndata: %s\n\n", b)
		return nil
	}
	var chunk struct {
		Bytes []byte `json:"bytes"` // base64 in JSON
	}
	if err := json.Unmarshal(payload, &chunk); err != nil || len(chunk.Bytes) == 0 {
		return nil // not an Anthropic chunk (e.g. initial-response): skip
	}
	var ev struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(chunk.Bytes, &ev)
	fmt.Fprintf(&s.buf, "event: %s\ndata: %s\n\n", ev.Type, chunk.Bytes)
	return nil
}

// eventHeader parses one header, returning string values (other types are skipped).
func eventHeader(b []byte) (name, val string, rest []byte, err error) {
	bad := errors.New("gateway: corrupt event stream header")
	if len(b) < 2 || len(b) < 2+int(b[0]) {
		return "", "", nil, bad
	}
	name, b = string(b[1:1+int(b[0])]), b[1+int(b[0]):]
	typ, b := b[0], b[1:]
	var n int
	switch typ {
	case 0, 1:
	case 2:
		n = 1
	case 3:
		n = 2
	case 4:
		n = 4
	case 5, 8:
		n = 8
	case 9:
		n = 16
	case 6, 7:
		if len(b) < 2 {
			return "", "", nil, bad
		}
		n = int(binary.BigEndian.Uint16(b))
		b = b[2:]
	default:
		return "", "", nil, bad
	}
	if len(b) < n {
		return "", "", nil, bad
	}
	if typ == 7 {
		val = string(b[:n])
	}
	return name, val, b[n:], nil
}
