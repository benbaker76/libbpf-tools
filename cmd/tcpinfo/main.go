package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event bpf tcpinfo.c -- -I../../headers

func net_bind_tcp(addr string) (int, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return -1, err
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return -1, err
	}

	// Set the SO_REUSEADDR socket option to allow binding to a port in use.
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	if err != nil {
		syscall.Close(fd)
		return -1, err
	}

	// Enable SO_REUSEPORT
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	if err != nil {
		log.Printf("Could not set SO_REUSEPORT socket option: %s", err)
	}

	sa := &syscall.SockaddrInet4{Port: tcpAddr.Port}
	copy(sa.Addr[:], tcpAddr.IP.To4())

	err = syscall.Bind(fd, sa)
	if err != nil {
		syscall.Close(fd)
		return -1, err
	}

	err = syscall.Listen(fd, syscall.SOMAXCONN)
	if err != nil {
		syscall.Close(fd)
		return -1, err
	}

	return fd, nil
}

func net_accept(sd int, clientAddr *net.TCPAddr) (int, error) {
	addr := &syscall.SockaddrInet4{Port: clientAddr.Port}
	copy(addr.Addr[:], clientAddr.IP.To4())
	fd, _, err := syscall.Accept(sd)
	if err != nil {
		return -1, err
	}
	return fd, nil
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	err := loadBpfObjects(&objs, nil)
	if err != nil {
		log.Fatalf("loadBpfObjects: %v", err)
	}
	defer objs.Close()

	// Attach the BPF program to the socket map
	err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.bpfMaps.SockMap.FD(),
		Program: objs.bpfPrograms.StreamParser,
		Attach:  ebpf.AttachSkSKBStreamParser,
	})
	if err != nil {
		log.Fatalf("RawAttachProgram: %v", err)
	}

	defer func() {
		// Detach the BPF program from the socket map
		err = link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  objs.bpfMaps.SockMap.FD(),
			Program: objs.bpfPrograms.StreamParser,
			Attach:  ebpf.AttachSkSKBStreamParser,
		})
		if err != nil {
			log.Fatalf("RawDetachProgram: %v", err)
		}
	}()

	// Attach the BPF program to the socket map
	err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.bpfMaps.SockMap.FD(),
		Program: objs.bpfPrograms.StreamVerdict,
		Attach:  ebpf.AttachSkSKBStreamVerdict,
	})
	if err != nil {
		log.Fatalf("RawAttachProgram: %v", err)
	}

	defer func() {
		// Detach the BPF program from the socket map
		err = link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  objs.bpfMaps.SockMap.FD(),
			Program: objs.bpfPrograms.StreamVerdict,
			Attach:  ebpf.AttachSkSKBStreamVerdict,
		})
		if err != nil {
			log.Fatalf("RawDetachProgram: %v", err)
		}
	}()

	rd, err := ringbuf.NewReader(objs.bpfMaps.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	go func() {
		<-stopper

		log.Fatalf("Exiting")

		err := rd.Close()
		if err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	log.Printf("%-16s %-8s %-16s %-15s %-6s -> %-15s %-6s",
		"Comm",
		"Pid",
		"User",
		"Src addr",
		"Port",
		"Dest addr",
		"Port",
	)

	listenAddr := "0.0.0.0:5000"

	if len(os.Args) > 1 {
		listenAddr = os.Args[1]
	}

	busyPoll := true // Set to true if you want to use SO_BUSY_POLL

	sd, err := net_bind_tcp(listenAddr)
	if err != nil {
		log.Fatalf("net_bind_tcp: %v", err)
	}
	defer syscall.Close(sd)

	clientAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} // Replace with the actual client address

	for {
		fd, err := net_accept(sd, clientAddr)
		if err != nil {
			log.Fatalf("net_accept: %v", err)
		}
		defer syscall.Close(fd)

		if busyPoll {
			// Set SO_BUSY_POLL if needed
			val := int(10 * 1000) // 10 ms in microseconds
			err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, unix.SO_BUSY_POLL, val)
			if err != nil {
				if err == syscall.EPERM {
					fmt.Println("[ ] Failed to set SO_BUSY_POLL. Are you CAP_NET_ADMIN?")
				} else {
					log.Fatalf("setsockopt(SOL_SOCKET, SO_BUSY_POLL): %v", err)
				}
			}
		}

		// Set a large SO_SNDBUF value
		val := int(32 * 1024 * 1024)
		err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, val)
		if err != nil {
			log.Fatalf("setsockopt(SOL_SOCKET, SO_SNDBUF): %v", err)
		}

		err = objs.bpfMaps.SockMap.Put(int32(0), int32(fd))
		if err != nil {
			log.Fatalf("SockMap.Put: %v", err)
		}

		pollfd := unix.PollFd{
			Fd:     int32(fd),
			Events: unix.POLLRDHUP,
		}
		_, err = unix.Poll([]unix.PollFd{pollfd}, -1)
		if err != nil {
			log.Fatalf("error during poll: %v", err)
		}

		// Was there a socket error?
		var errnum int
		errlen := uint32(4)
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), syscall.SOL_SOCKET, syscall.SO_ERROR, uintptr(unsafe.Pointer(&errnum)), uintptr(unsafe.Pointer(&errlen)), 0)
		if errno != 0 {
			log.Fatalf("error getting socket option: %v", errno)
		}
		if errnum != 0 {
			fmt.Printf("Socket error: %v\n", errnum)
		}

		// Get byte count from TCP_INFO
		var ti syscall.TCPInfo
		tiLen := uint32(unsafe.Sizeof(ti))
		_, _, errno = syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), syscall.IPPROTO_TCP, syscall.TCP_INFO, uintptr(unsafe.Pointer(&ti)), uintptr(unsafe.Pointer(&tiLen)), 0)
		if errno != 0 {
			log.Fatalf("error getting TCP_INFO: %v", errno)
		}

		// You can now use 'ti' for further processing.
		//fmt.Printf("TCPInfo: %+v\n", ti)

		// bpfEvent is generated by bpf2go.
		var event bpfEvent
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.BigEndian, &event)
		if err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		user, err := user.LookupId(strconv.Itoa(int(event.Uid)))
		if err != nil {
			log.Printf("looking up uid: %s", err)
			continue
		}

		log.Printf("%-16s %-8d %-16s %-15s %-6d -> %-15s %-6d",
			event.Comm,
			event.Pid,
			user.Username,
			intToIP(event.Saddr),
			event.Sport,
			intToIP(event.Daddr),
			event.Dport,
		)

		err = objs.bpfMaps.SockMap.Delete(int32(0))
		if err != nil {
			log.Fatalf("SockMap.Delete: %v", err)
		}

		syscall.Close(fd)
	}
}
