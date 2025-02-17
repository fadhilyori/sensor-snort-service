package listener

import (
	"net"
	"os"
)

const (
	AlertMsgSize      = 256
	PcapHeaderSize    = 16 // 4 x uint32: ts_sec, ts_usec, caplen, len
	HeaderAfterPcap   = 20 // 5 x uint32: dlthdr, nethdr, transhdr, data, val
	PacketFieldSize   = 65535
	TailFieldsSize    = 36 // 9 x uint32: gid, sid, rev, class_id, priority, event_id, event_ref, ts_sec, ts_usec
	ExpectedSizeNoPad = AlertMsgSize + PcapHeaderSize + HeaderAfterPcap + PacketFieldSize + TailFieldsSize // 65863 bytes
	ExpectedSizePad   = ExpectedSizeNoPad + 1 // 65864 bytes (if there’s a 1-byte padding after packet field)
)

type UnixSocketListener struct {
	socketPath string
	listener   *net.UnixConn
}

func NewSocketListener(socketPath string) (*UnixSocketListener, error) {
	// Remove existing socket if it exists
	if _, err := os.Stat(socketPath); os.IsExist(err) {
		if err := os.Remove(socketPath); err != nil {
			return nil, err
		}
	}

	addr, err := net.ResolveUnixAddr("unixgram", socketPath)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		return nil, err
	}

	return &UnixSocketListener{
		socketPath: socketPath,
		listener:   conn,
	}, nil
}

func (l *UnixSocketListener) Close() error {
	defer os.Remove(l.socketPath)
	return l.listener.Close()
}

func (l *UnixSocketListener) Receive() ([]byte, error) {
	buf := make([]byte, 65535)
	n, _, err := l.listener.ReadFromUnix(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (l *UnixSocketListener) Serve(handler func([]byte)) error {
	for {
		packet, err := l.Receive()
		if err != nil {
			return err
		}
		go handler(packet)
	}
}
