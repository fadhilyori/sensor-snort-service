package listener

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	AlertMsgSize      = 256
	PcapHeaderSize    = 16 // 4 x uint32: ts_sec, ts_usec, caplen, len
	HeaderAfterPcap   = 20 // 5 x uint32: dlthdr, nethdr, transhdr, data, val
	PacketFieldSize   = 65535
	TailFieldsSize    = 36                                                                                 // 9 x uint32: gid, sid, rev, class_id, priority, event_id, event_ref, ts_sec, ts_usec
	ExpectedSizeNoPad = AlertMsgSize + PcapHeaderSize + HeaderAfterPcap + PacketFieldSize + TailFieldsSize // 65863 bytes
	ExpectedSizePad   = ExpectedSizeNoPad + 1                                                              // 65864 bytes (if there's a 1-byte padding after packet field)
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
	buf := make([]byte, ExpectedSizePad)
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

type Pkt struct {
	SrcMAC    string
	DstMAC    string
	EtherType string
}

// AlertPacket holds the parsed fields from Snort3’s alert_unixsock packet.
type AlertPacket struct {
	// Alert message (null-terminated string)
	AlertMsg string

	// pcap header fields
	PcapTsSec  uint32
	PcapTsUsec uint32
	CapLen     uint32
	OrigLen    uint32

	// Offsets from the original packet buffer.
	DltHdr   uint32 // datalink header (e.g., Ethernet)
	NetHdr   uint32 // network header (e.g., IPv4)
	TransHdr uint32 // transport header (e.g., TCP)
	DataOff  uint32
	Val      uint32

	// Packet data (only the first CapLen bytes are valid)
	Pkt []byte

	// Tail fields
	Gid      uint32
	Sid      uint32
	Rev      uint32
	ClassID  uint32
	Priority uint32
	EventID  uint32
	EventRef uint32
	TsSec    uint32
	TsUsec   uint32
}

// ParseAlertPacket parses the raw datagram (received from Snort3) into an AlertPacket.
func ParseAlertPacket(data []byte) (*AlertPacket, error) {
	// Determine the tail offset based on the overall packet size.
	var tailOffset int
	if len(data) == ExpectedSizeNoPad {
		tailOffset = AlertMsgSize + PcapHeaderSize + HeaderAfterPcap + PacketFieldSize
	} else if len(data) == ExpectedSizePad {
		tailOffset = AlertMsgSize + PcapHeaderSize + HeaderAfterPcap + PacketFieldSize + 1
	} else {
		return nil, errors.New("unexpected packet size")
	}

	ap := &AlertPacket{}
	reader := bytes.NewReader(data)

	// 1. Read the alert message (256 bytes).
	alertMsgBytes := make([]byte, AlertMsgSize)
	if err := binary.Read(reader, binary.LittleEndian, &alertMsgBytes); err != nil {
		return nil, err
	}
	ap.AlertMsg = strings.TrimRight(string(alertMsgBytes), "\x00")

	// 2. Read the pcap header (4 x uint32).
	var pcapFields [4]uint32
	if err := binary.Read(reader, binary.LittleEndian, &pcapFields); err != nil {
		return nil, err
	}
	ap.PcapTsSec = pcapFields[0]
	ap.PcapTsUsec = pcapFields[1]
	ap.CapLen = pcapFields[2]
	ap.OrigLen = pcapFields[3]

	// 3. Read the 5 header fields after the pcap header.
	var hdrFields [5]uint32
	if err := binary.Read(reader, binary.LittleEndian, &hdrFields); err != nil {
		return nil, err
	}
	ap.DltHdr = hdrFields[0]
	ap.NetHdr = hdrFields[1]
	ap.TransHdr = hdrFields[2]
	ap.DataOff = hdrFields[3]
	ap.Val = hdrFields[4]

	// 4. Read the fixed packet field (65,535 bytes).
	pktField := make([]byte, PacketFieldSize)
	if err := binary.Read(reader, binary.LittleEndian, &pktField); err != nil {
		return nil, err
	}
	// Only the first CapLen bytes are valid.
	if ap.CapLen > PacketFieldSize {
		return nil, errors.New("caplen exceeds maximum packet field size")
	}
	ap.Pkt = pktField[:ap.CapLen]

	// 5. Use tailOffset to reposition the reader before reading the tail fields.
	if _, err := reader.Seek(int64(tailOffset), 0); err != nil {
		return nil, err
	}

	// 6. Read the tail fields (9 x uint32).
	var tailFields [9]uint32
	if err := binary.Read(reader, binary.LittleEndian, &tailFields); err != nil {
		return nil, err
	}
	ap.Gid = tailFields[0]
	ap.Sid = tailFields[1]
	ap.Rev = tailFields[2]
	ap.ClassID = tailFields[3]
	ap.Priority = tailFields[4]
	ap.EventID = tailFields[5]
	ap.EventRef = tailFields[6]
	ap.TsSec = tailFields[7]
	ap.TsUsec = tailFields[8]

	return ap, nil
}

func ParseRawPacket(data []byte) (*Pkt, error) {

	packets := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

	fmt.Printf("Decoded packet layers: \n")
	for _, layer := range packets.Layers() {
		fmt.Printf("- %s\n", layer.LayerType())
	}

	if ethLayer := packets.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		srcMAC := eth.SrcMAC.String()
		dstMAC := eth.DstMAC.String()
		etherType := eth.EthernetType.String()

		fmt.Printf("Source MAC: %s\n", srcMAC)
		fmt.Printf("Destination MAC: %s\n", dstMAC)
		fmt.Printf("EtherType: %s\n", etherType)
	}

	return nil, nil
}
