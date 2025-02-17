package listener

import (
	"net"
	"os"
)

type UnixSocketListener struct {
	socketPath string
	listener   net.Listener
}

func NewSocketListener(socketPath string) (*UnixSocketListener, error) {
	// Remove existing socket if it exists
	if _, err := os.Stat(socketPath); os.IsExist(err) {
		if err := os.Remove(socketPath); err != nil {
			return nil, err
		}
	}

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}

	if err := os.Chmod(socketPath, 0777); err != nil {
		l.Close()
		return nil, err
	}

	return &UnixSocketListener{
		socketPath: socketPath,
		listener:   l,
	}, nil
}
func (l *UnixSocketListener) Accept() (net.Conn, error) {
	return l.listener.Accept()
}

func (l *UnixSocketListener) Close() error {
	defer os.Remove(l.socketPath)
	return l.listener.Close()
}

func (l *UnixSocketListener) Serve(handler func(conn net.Conn)) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go handler(conn)
	}
}
