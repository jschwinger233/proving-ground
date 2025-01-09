package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	listener, err := net.Listen("tcp6", "[::1]:8080")
	if err != nil {
		fmt.Printf("Error starting server: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()

	if err := setListenerSocketMark(listener, 0xa00); err != nil {
		fmt.Printf("Error setting SO_MARK on listener: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Server listening on 8080\n")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Error accepting connection: %v\n", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	buffer := make([]byte, 1024)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			fmt.Printf("Error reading from connection: %v\n", err)
			return
		}

		_, err = conn.Write(buffer[:n])
		if err != nil {
			fmt.Printf("Error writing to connection: %v\n", err)
			return
		}
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT)
		<-sigs
		println("Received SIGINT, closing connection")
		conn.Close()
		break
	}
}

func setListenerSocketMark(listener net.Listener, mark int) error {
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		return fmt.Errorf("listener is not a TCP listener")
	}

	file, err := tcpListener.File()
	if err != nil {
		return fmt.Errorf("error getting file descriptor: %v", err)
	}
	defer file.Close()

	fd := int(file.Fd())

	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, mark); err != nil {
		return fmt.Errorf("error setting SO_MARK: %v", err)
	}

	return nil
}
