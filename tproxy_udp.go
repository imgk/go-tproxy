//go:build linux

package tproxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ListenUDP will construct a new UDP listener
// socket with the Linux IP_TRANSPARENT option
// set on the underlying socket
func ListenUDP(network string, laddr *net.UDPAddr) (PacketConn, error) {
	conn := PacketConn{}
	listener, err := net.ListenUDP(network, laddr)
	if err != nil {
		return conn, err
	}

	ipv6 := laddr.IP.To4() == nil

	fileDescriptorSource, err := listener.File()
	if err != nil {
		return conn, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: laddr, Err: fmt.Errorf("get file descriptor: %s", err)}
	}
	defer fileDescriptorSource.Close()

	fileDescriptor := int(fileDescriptorSource.Fd())

	if ipv6 {

		if err = unix.SetsockoptInt(fileDescriptor, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
			return conn, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: laddr, Err: fmt.Errorf("set socket option: IPV6_TRANSPARENT: %s", err)}
		}

		if err = unix.SetsockoptInt(fileDescriptor, unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1); err != nil {
			return conn, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: laddr, Err: fmt.Errorf("set socket option: IPV6_RECVORIGDSTADDR: %s", err)}
		}

	} else {

		if err = unix.SetsockoptInt(fileDescriptor, unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
			return conn, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: laddr, Err: fmt.Errorf("set socket option: IP_TRANSPARENT: %s", err)}
		}

		if err = unix.SetsockoptInt(fileDescriptor, unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1); err != nil {
			return conn, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: laddr, Err: fmt.Errorf("set socket option: IP_RECVORIGDSTADDR: %s", err)}
		}

	}

	conn.UDPConn = listener
	return conn, nil
}

// PacketConn wraps net.UDPConn to show difference
type PacketConn struct {
	*net.UDPConn
}

// ReadFromUDPTProxy reads a UDP packet from c, copying the payload into b.
// It returns the number of bytes copied into b and the return address
// that was on the packet.
//
// Out-of-band data is also read in so that the original destination
// address can be identified and parsed.
func (conn PacketConn) ReadFromUDPTProxy(b []byte) (int, *net.UDPAddr, *net.UDPAddr, error) {
	oob := make([]byte, 1024)
	n, oobn, _, addr, err := conn.ReadMsgUDP(b, oob)
	if err != nil {
		return 0, nil, nil, err
	}

	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return 0, nil, nil, fmt.Errorf("parsing socket control message: %s", err)
	}

	var originalDst *net.UDPAddr
	for _, msg := range msgs {
		if msg.Header.Level == unix.SOL_IP && msg.Header.Type == unix.IP_RECVORIGDSTADDR {
			originalDstRaw := &unix.RawSockaddrInet4{}
			if err = binary.Read(bytes.NewReader(msg.Data), binary.LittleEndian, originalDstRaw); err != nil {
				return 0, nil, nil, fmt.Errorf("reading original destination address: %s", err)
			}

			switch originalDstRaw.Family {
			case unix.AF_INET:
				pp := (*unix.RawSockaddrInet4)(unsafe.Pointer(originalDstRaw))
				p := (*[2]byte)(unsafe.Pointer(&pp.Port))
				originalDst = &net.UDPAddr{
					IP:   net.IPv4(pp.Addr[0], pp.Addr[1], pp.Addr[2], pp.Addr[3]),
					Port: int(p[0])<<8 + int(p[1]),
				}

			default:
				return 0, nil, nil, fmt.Errorf("original destination is an unsupported network family")
			}
		}

		if msg.Header.Level == unix.SOL_IPV6 && msg.Header.Type == unix.IPV6_RECVORIGDSTADDR {
			originalDstRaw := &unix.RawSockaddrInet6{}
			if err = binary.Read(bytes.NewReader(msg.Data), binary.LittleEndian, originalDstRaw); err != nil {
				return 0, nil, nil, fmt.Errorf("reading original destination address: %s", err)
			}

			switch originalDstRaw.Family {
			case unix.AF_INET6:
				pp := (*unix.RawSockaddrInet6)(unsafe.Pointer(originalDstRaw))
				p := (*[2]byte)(unsafe.Pointer(&pp.Port))
				originalDst = &net.UDPAddr{
					IP:   net.IP(pp.Addr[:]),
					Port: int(p[0])<<8 + int(p[1]),
					Zone: "", //not needed in our context, but kept for ref: strconv.Itoa(int(pp.Scope_id)),
				}

			default:
				return 0, nil, nil, fmt.Errorf("original destination is an unsupported network family")
			}

		}

	}

	if originalDst == nil {
		return 0, nil, nil, fmt.Errorf("unable to obtain original destination: %s - msgs: %+v", err, msgs)
	}

	return n, addr, originalDst, nil
}

// ReadFromUDPAddrPortTProxy reads a UDP packet from c, copying the payload into b.
// It returns the number of bytes copied into b and the return address
// that was on the packet.
//
// Out-of-band data is also read in so that the original destination
// address can be identified and parsed.
func (conn PacketConn) ReadFromUDPAddrPortTProxy(b []byte) (int, netip.AddrPort, netip.AddrPort, error) {
	var originalDst netip.AddrPort
	var parsedDst bool = false

	oob := make([]byte, 1024)
	n, oobn, _, addr, err := conn.ReadMsgUDPAddrPort(b, oob)
	if err != nil {
		return 0, addr, originalDst, err
	}

	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return 0, addr, originalDst, fmt.Errorf("parsing socket control message: %s", err)
	}

	for _, msg := range msgs {
		if msg.Header.Level == unix.SOL_IP && msg.Header.Type == unix.IP_RECVORIGDSTADDR {
			originalDstRaw := &unix.RawSockaddrInet4{}
			if err = binary.Read(bytes.NewReader(msg.Data), binary.LittleEndian, originalDstRaw); err != nil {
				return 0, addr, originalDst, fmt.Errorf("reading original destination address: %s", err)
			}

			switch originalDstRaw.Family {
			case unix.AF_INET:
				pp := (*unix.RawSockaddrInet4)(unsafe.Pointer(originalDstRaw))
				p := (*[2]byte)(unsafe.Pointer(&pp.Port))
				parsedDst = true
				originalDst = netip.AddrPortFrom(netip.AddrFrom4(pp.Addr), uint16(p[0])<<8|uint16(p[1]))
			default:
				return 0, addr, originalDst, fmt.Errorf("original destination is an unsupported network family")
			}
		}

		if msg.Header.Level == unix.SOL_IPV6 && msg.Header.Type == unix.IPV6_RECVORIGDSTADDR {
			originalDstRaw := &unix.RawSockaddrInet6{}
			if err = binary.Read(bytes.NewReader(msg.Data), binary.LittleEndian, originalDstRaw); err != nil {
				return 0, addr, originalDst, fmt.Errorf("reading original destination address: %s", err)
			}

			switch originalDstRaw.Family {
			case unix.AF_INET6:
				pp := (*unix.RawSockaddrInet6)(unsafe.Pointer(originalDstRaw))
				p := (*[2]byte)(unsafe.Pointer(&pp.Port))
				parsedDst = true
				originalDst = netip.AddrPortFrom(netip.AddrFrom16(pp.Addr), uint16(p[0])<<8|uint16(p[1]))
			default:
				return 0, addr, originalDst, fmt.Errorf("original destination is an unsupported network family")
			}

		}

	}

	if !parsedDst {
		return 0, addr, originalDst, fmt.Errorf("unable to obtain original destination: %s - msgs: %+v", err, msgs)
	}

	return n, addr, originalDst, nil
}

// DialUDP connects to the remote address raddr on the network net,
// which must be "udp", "udp4", or "udp6".  If laddr is not nil, it is
// used as the local address for the connection.
func DialUDP(network string, laddr *net.UDPAddr, raddr *net.UDPAddr) (PacketConn, error) {
	remoteSocketAddress, err := udpAddrToSocketAddr(raddr)
	if err != nil {
		return PacketConn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("build destination socket address: %s - %+v", err, raddr)}
	}

	ipv6 := laddr.IP.To4() == nil

	localSocketAddress, err := udpAddrToSocketAddr(laddr)
	if err != nil {
		return PacketConn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("build local socket address: %s", err)}
	}

	fileDescriptor, err := unix.Socket(udpAddrFamily(network, laddr, raddr), unix.SOCK_DGRAM, 0)
	if err != nil {
		return PacketConn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("socket open: %s", err)}
	}

	if err = unix.SetsockoptInt(fileDescriptor, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		unix.Close(fileDescriptor)
		return PacketConn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("set socket option: SO_REUSEADDR: %s", err)}
	}

	if ipv6 {

		if err = unix.SetsockoptInt(fileDescriptor, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
			unix.Close(fileDescriptor)
			return PacketConn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("set socket option: IPV6_TRANSPARENT: %s", err)}
		}

	} else {

		if err = unix.SetsockoptInt(fileDescriptor, unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
			unix.Close(fileDescriptor)
			return PacketConn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("set socket option: IP_TRANSPARENT: %s", err)}
		}

	}

	if err = unix.Bind(fileDescriptor, localSocketAddress); err != nil {
		unix.Close(fileDescriptor)
		return PacketConn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("socket bind: %s", err)}
	}

	if err = unix.Connect(fileDescriptor, remoteSocketAddress); err != nil {
		unix.Close(fileDescriptor)
		return PacketConn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("socket connect: %s", err)}
	}

	fdFile := os.NewFile(uintptr(fileDescriptor), fmt.Sprintf("net-udp-dial-%s", raddr.String()))
	defer fdFile.Close()

	remoteConn, err := net.FileConn(fdFile)
	if err != nil {
		unix.Close(fileDescriptor)
		return PacketConn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("convert file descriptor to connection: %s", err)}
	}

	return PacketConn{remoteConn.(*net.UDPConn)}, nil
}

// udpAddToSockerAddr will convert a UDPAddr
// into a Sockaddr that may be used when
// connecting and binding sockets
func udpAddrToSocketAddr(addr *net.UDPAddr) (unix.Sockaddr, error) {
	switch {
	case addr.IP.To4() != nil:
		ip := [4]byte{}
		copy(ip[:], addr.IP.To4())

		return &unix.SockaddrInet4{Addr: ip, Port: addr.Port}, nil

	default:
		ip := [16]byte{}
		copy(ip[:], addr.IP.To16())

		var zoneID uint64
		if addr.Zone != "" {
			zoneIDparsed, err := strconv.ParseUint(addr.Zone, 10, 32)
			if err != nil {
				return nil, err
			}
			zoneID = zoneIDparsed
		}

		return &unix.SockaddrInet6{Addr: ip, Port: addr.Port, ZoneId: uint32(zoneID)}, nil
	}
}

// udpAddrFamily will attempt to work
// out the address family based on the
// network and UDP addresses
func udpAddrFamily(net string, laddr, raddr *net.UDPAddr) int {
	switch net[len(net)-1] {
	case '4':
		return unix.AF_INET
	case '6':
		return unix.AF_INET6
	}

	if (laddr == nil || laddr.IP.To4() != nil) &&
		(raddr == nil || raddr.IP.To4() != nil) {
		return unix.AF_INET
	}
	return unix.AF_INET6
}
