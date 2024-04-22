package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <netloc>\ne.g. \"%s localhost:8000\"\n", os.Args[0], os.Args[0])
		os.Exit(1)
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", os.Args[1])
	if err != nil {
		fmt.Println("Error resolving TCP address:", err)
		os.Exit(1)
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		fmt.Println("Error dialing TCP:", err)
		os.Exit(1)
	}
	defer conn.Close()

	request := "GET / HTTP/1.0\r\n\r\n"
	_, err = conn.Write([]byte(request))
	if err != nil {
		fmt.Println("Error writing to TCP connection:", err)
		os.Exit(1)
	}

	n, err := conn.WriteTo(os.Stdout)
	if err != nil {
		fmt.Println("Error reading from TCP connection:", err)
		os.Exit(1)
	}
	fmt.Printf("Read %d bytes\n", n)
}
