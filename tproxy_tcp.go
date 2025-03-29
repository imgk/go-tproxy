//go:build linux

package tproxy

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Listener describes a TCP Listener
// with the Linux IP_TRANSPARENT option defined
// on the listening socket
type TCPListener struct {
	*net.TCPListener
}

// Accept waits for and returns
// the next connection to the listener.
//
// This command wraps the AcceptTProxy
// method of the Listener
func (ln TCPListener) Accept() (net.Conn, error) {
	return ln.AcceptTProxy()
}

// AcceptTProxy will accept a TCP connection
// and wrap it to a TProxy connection to provide
// TProxy functionality
func (ln TCPListener) AcceptTProxy() (Conn, error) {
	tcpConn, err := ln.TCPListener.AcceptTCP()
	if err != nil {
		return Conn{}, err
	}

	return Conn{TCPConn: tcpConn}, nil
}

// Addr returns the network address
// the listener is accepting connections
// from
func (ln TCPListener) Addr() net.Addr {
	return ln.TCPListener.Addr()
}

// Close will close the listener from accepting
// any more connections. Any blocked connections
// will unblock and close
func (ln TCPListener) Close() error {
	return ln.TCPListener.Close()
}

// ListenTCP will construct a new TCP listener
// socket with the Linux IP_TRANSPARENT option
// set on the underlying socket
func ListenTCP(network string, laddr *net.TCPAddr) (TCPListener, error) {
	ln := TCPListener{}
	listener, err := net.ListenTCP(network, laddr)
	if err != nil {
		return ln, err
	}

	fileDescriptorSource, err := listener.File()
	if err != nil {
		return ln, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: laddr, Err: fmt.Errorf("get file descriptor: %s", err)}
	}
	defer fileDescriptorSource.Close()

	if err = unix.SetsockoptInt(int(fileDescriptorSource.Fd()), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
		return ln, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: laddr, Err: fmt.Errorf("set socket option: IP_TRANSPARENT: %s", err)}
	}

	ln.TCPListener = listener
	return ln, nil
}

// Conn describes a connection
// accepted by the TProxy listener.
//
// It is simply a TCP connection with
// the ability to dial a connection to
// the original destination while assuming
// the IP address of the client
type Conn struct {
	*net.TCPConn
}

// DialOriginalDestination will open a
// TCP connection to the original destination
// that the client was trying to connect to before
// being intercepted.
//
// When `dontAssumeRemote` is false, the connection will
// originate from the IP address and port that the client
// used when making the connection. Otherwise, when true,
// the connection will originate from an IP address and port
// assigned by the Linux kernel that is owned by the
// operating system
func (conn Conn) DialOriginalDestination(dontAssumeRemote bool) (Conn, error) {
	remoteSocketAddress, err := tcpAddrToSocketAddr(conn.LocalAddr().(*net.TCPAddr))
	if err != nil {
		return Conn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("build destination socket address: %s", err)}
	}

	localSocketAddress, err := tcpAddrToSocketAddr(conn.RemoteAddr().(*net.TCPAddr))
	if err != nil {
		return Conn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("build local socket address: %s", err)}
	}

	fileDescriptor, err := unix.Socket(tcpAddrFamily("tcp", conn.LocalAddr().(*net.TCPAddr), conn.RemoteAddr().(*net.TCPAddr)), unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		return Conn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("socket open: %s", err)}
	}

	if err = unix.SetsockoptInt(fileDescriptor, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		unix.Close(fileDescriptor)
		return Conn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("set socket option: SO_REUSEADDR: %s", err)}
	}

	if err = unix.SetsockoptInt(fileDescriptor, unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
		unix.Close(fileDescriptor)
		return Conn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("set socket option: IP_TRANSPARENT: %s", err)}
	}

	if err = unix.SetNonblock(fileDescriptor, true); err != nil {
		unix.Close(fileDescriptor)
		return Conn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("set socket option: SO_NONBLOCK: %s", err)}
	}

	if !dontAssumeRemote {
		if err = unix.Bind(fileDescriptor, localSocketAddress); err != nil {
			unix.Close(fileDescriptor)
			return Conn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("socket bind: %s", err)}
		}
	}

	if err = unix.Connect(fileDescriptor, remoteSocketAddress); err != nil && !strings.Contains(err.Error(), "operation now in progress") {
		unix.Close(fileDescriptor)
		return Conn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("socket connect: %s", err)}
	}

	fdFile := os.NewFile(uintptr(fileDescriptor), fmt.Sprintf("net-tcp-dial-%s", conn.LocalAddr().String()))
	defer fdFile.Close()

	remoteConn, err := net.FileConn(fdFile)
	if err != nil {
		unix.Close(fileDescriptor)
		return Conn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("convert file descriptor to connection: %s", err)}
	}

	return Conn{remoteConn.(*net.TCPConn)}, nil
}

// DialTCP creates transparent connection
// network must be "tcp", "tcp4" or "tcp6"
// if laddr is nil, use dontAssumeRemote as false
func DialTCP(network string, laddr, raddr *net.TCPAddr) (Conn, error) {
	remoteSocketAddress, err := tcpAddrToSocketAddr(raddr)
	if err != nil {
		return Conn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("build destination socket address: %s", err)}
	}

	fileDescriptor, err := unix.Socket(tcpAddrFamily("tcp", raddr, laddr), unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		return Conn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("socket open: %s", err)}
	}

	if err = unix.SetsockoptInt(fileDescriptor, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		unix.Close(fileDescriptor)
		return Conn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("set socket option: SO_REUSEADDR: %s", err)}
	}

	if err = unix.SetsockoptInt(fileDescriptor, unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
		unix.Close(fileDescriptor)
		return Conn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("set socket option: IP_TRANSPARENT: %s", err)}
	}

	if err = unix.SetNonblock(fileDescriptor, true); err != nil {
		unix.Close(fileDescriptor)
		return Conn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("set socket option: SO_NONBLOCK: %s", err)}
	}

	if laddr != nil {
		localSocketAddress, err := tcpAddrToSocketAddr(laddr)
		if err != nil {
			return Conn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("build local socket address: %s", err)}
		}

		if err = unix.Bind(fileDescriptor, localSocketAddress); err != nil {
			unix.Close(fileDescriptor)
			return Conn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("socket bind: %s", err)}
		}
	}

	if err = unix.Connect(fileDescriptor, remoteSocketAddress); err != nil && !strings.Contains(err.Error(), "operation now in progress") {
		unix.Close(fileDescriptor)
		return Conn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("socket connect: %s", err)}
	}

	fdFile := os.NewFile(uintptr(fileDescriptor), fmt.Sprintf("net-tcp-dial-%s", raddr.String()))
	defer fdFile.Close()

	remoteConn, err := net.FileConn(fdFile)
	if err != nil {
		unix.Close(fileDescriptor)
		return Conn{}, &net.OpError{Op: "dial", Err: fmt.Errorf("convert file descriptor to connection: %s", err)}
	}

	return Conn{remoteConn.(*net.TCPConn)}, nil
}

// tcpAddToSockerAddr will convert a TCPAddr
// into a Sockaddr that may be used when
// connecting and binding sockets
func tcpAddrToSocketAddr(addr *net.TCPAddr) (unix.Sockaddr, error) {
	switch {
	case addr.IP.To4() != nil:
		ip := [4]byte{}
		copy(ip[:], addr.IP.To4())

		return &unix.SockaddrInet4{Addr: ip, Port: addr.Port}, nil

	default:
		ip := [16]byte{}
		copy(ip[:], addr.IP.To16())

		zoneID, err := strconv.ParseUint(addr.Zone, 10, 32)
		if err != nil {
			return nil, err
		}

		return &unix.SockaddrInet6{Addr: ip, Port: addr.Port, ZoneId: uint32(zoneID)}, nil
	}
}

// tcpAddrFamily will attempt to work
// out the address family based on the
// network and TCP addresses
func tcpAddrFamily(net string, laddr, raddr *net.TCPAddr) int {
	switch net[len(net)-1] {
	case '4':
		return unix.AF_INET
	case '6':
		return unix.AF_INET6
	}

	if (laddr == nil || laddr.IP.To4() != nil) &&
		(raddr == nil || laddr.IP.To4() != nil) {
		return unix.AF_INET
	}
	return unix.AF_INET6
}
