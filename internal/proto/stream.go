package proto

import (
	"encoding/binary"
	"errors"
	"io"
)

// StreamPreface is the first thing a client writes on every smux stream: the user's
// auth token and the destination the server should connect the stream to. Keeping it
// per-stream makes the server stateless about sessions and lets every stream be
// authorized and accounted independently.
type StreamPreface struct {
	Token string // per-user auth token
	Dest  string // "host:port" the exit should dial, or a reserved name like "echo"
}

const maxPrefaceField = 2048

// WriteTo writes the preface as two uint16-length-prefixed fields.
func (p StreamPreface) WriteTo(w io.Writer) (int64, error) {
	if len(p.Token) > maxPrefaceField || len(p.Dest) > maxPrefaceField {
		return 0, errors.New("proto: preface field too long")
	}
	buf := make([]byte, 0, 4+len(p.Token)+len(p.Dest))
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(p.Token)))
	buf = append(buf, hdr[:]...)
	buf = append(buf, p.Token...)
	binary.BigEndian.PutUint16(hdr[:], uint16(len(p.Dest)))
	buf = append(buf, hdr[:]...)
	buf = append(buf, p.Dest...)
	n, err := w.Write(buf)
	return int64(n), err
}

// ReadPreface reads a StreamPreface written by WriteTo.
func ReadPreface(r io.Reader) (StreamPreface, error) {
	readField := func() (string, error) {
		var hdr [2]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return "", err
		}
		n := binary.BigEndian.Uint16(hdr[:])
		if int(n) > maxPrefaceField {
			return "", errors.New("proto: preface field too long")
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return string(b), nil
	}
	tok, err := readField()
	if err != nil {
		return StreamPreface{}, err
	}
	dst, err := readField()
	if err != nil {
		return StreamPreface{}, err
	}
	return StreamPreface{Token: tok, Dest: dst}, nil
}
