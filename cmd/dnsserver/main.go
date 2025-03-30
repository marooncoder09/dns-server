package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/codecrafters-io/dns-server-starter-go/internal/server"
)

const (
	PORT = "2053"
	IP   = "127.0.0.1"
)

func main() {
	resolverAddr := flag.String("resolver", "", "Upstream DNS resolver address (ip:port)")
	flag.Parse()

	if *resolverAddr == "" {
		fmt.Println("Error: --resolver flag is required")
		os.Exit(1)
	}

	fmt.Println("Starting DNS server...")
	startServer(*resolverAddr)
}

func startServer(resolverAddr string) {
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%s", IP, PORT))
	if err != nil {
		fmt.Printf("Failed to resolve UDP address: %v\n", err)
		os.Exit(1)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Printf("Failed to bind to address: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	handler := server.NewHandler(resolverAddr)
	buf := make([]byte, 512)

	for {
		size, source, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Printf("Error receiving data: %v\n", err)
			continue
		}
		go handler.HandleRequest(conn, source, buf[:size])
	}
}
