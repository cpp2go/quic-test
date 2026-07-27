package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"

	"quic-test/quic"
)

func main() {
	if err := echoServer(); err != nil {
		log.Fatal(err)
	}
}

// echoServer 启动纯 QUIC 回显服务端（多地址监听）
func echoServer() error {
	// 同时监听 IPv6（双栈）和 IPv4
	// Windows: IPv6 默认双栈，先绑 IPv6；若失败则绑 IPv4
	udpConns := make([]*net.UDPConn, 0, 2)

	for _, addr := range []string{"[::]:4242", "0.0.0.0:4242"} {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			log.Printf("跳过 %s: %v", addr, err)
			continue
		}
		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			log.Printf("跳过 %s: %v", addr, err)
			continue
		}
		udpConns = append(udpConns, conn)
		fmt.Println("监听:", conn.LocalAddr())
	}

	if len(udpConns) == 0 {
		return fmt.Errorf("没有可用的监听地址")
	}

	cfg := &quic.Config{
		CongestionControl: quic.CongestionCUBIC, // 可选: CUBIC / BBR / NewReno
	}
	listener := quic.ListenAddrs(udpConns, cfg)
	defer listener.Close()

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			fmt.Println("Accept error:", err)
			return err
		}

		fmt.Printf("接受新连接: %s -> %s\n", conn.LocalAddr(), conn.RemoteAddr())

		go handleConnection(conn)
	}
}

func handleConnection(conn *quic.Connection) {
	defer conn.CloseWithError(0, "bye")

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			fmt.Println("AcceptStream error:", err)
			return
		}

		fmt.Printf("接受新流: %d\n", stream.StreamID())
		go handleStream(stream)
	}
}

func handleStream(stream *quic.Stream) {
	defer stream.Close()

	buf := make([]byte, 1024)
	for {
		n, err := stream.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Println("读取错误:", err)
			}
			break
		}
		fmt.Printf("收到消息: %s, %d 字节\n", string(buf[:n]), n)

		// 回显
		_, err = stream.Write(buf[:n])
		if err != nil {
			fmt.Println("写入错误:", err)
			break
		}
	}
}
