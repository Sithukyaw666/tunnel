package proto

import (
	"encoding/binary"
	"io"
)

const AuthSucceed = "succeed"
const AuthFail = "fail"
const HeaderSize = 4 // 4 byte for prefix

func Send(conn io.Writer, payload string) error {
	buf := make([]byte, HeaderSize+len(payload))
	binary.BigEndian.PutUint32(buf[:HeaderSize], uint32(len(payload)))
	copy(buf[HeaderSize:], []byte(payload))
	if _, err := conn.Write(buf); err != nil {
		return err
	}
	return nil
}

func Receive(conn io.Reader) ([]byte, error) {
	var header [HeaderSize]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
