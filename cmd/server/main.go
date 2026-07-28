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

// echoServer 启动纯 QUIC 回显服务端（自动绑定所有 IP）
func echoServer() error {
	// 遍历本机所有网卡 IP 逐一绑定
	udpConns, err := listenAllIPs(4242)
	if err != nil {
		return err
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

// listenAllIPs 遍历本机所有网卡，对每个 IP 地址尝试绑定 UDP 端口。
func listenAllIPs(port int) ([]*net.UDPConn, error) {
	seen := make(map[string]bool) // 去重
	var conns []*net.UDPConn

	// 先尝试通配地址
	// 注意: Windows 上 IPv6 默认双栈，[::]:port 会同时占用 IPv4，
	// 此时再绑 0.0.0.0:port 会报 EADDRINUSE，跳过即可。
	for _, addr := range []string{fmt.Sprintf("[::]:%d", port), fmt.Sprintf("0.0.0.0:%d", port)} {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			log.Printf("解析 %s 失败: %v", addr, err)
			continue
		}
		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			// Windows 双栈下 0.0.0.0 绑定冲突属正常现象
			fmt.Printf("  (%s 已被占用，跳过)\n", addr)
			continue
		}
		conns = append(conns, conn)
		fmt.Println("监听:", conn.LocalAddr())
		seen[conn.LocalAddr().String()] = true
	}

	// 遍历所有网卡补充绑定具体 IP
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("获取网卡列表失败: %v", err)
		return conns, nil
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}

			addrStr := net.JoinHostPort(ip.String(), fmt.Sprint(port))
			if seen[addrStr] {
				continue
			}
			seen[addrStr] = true

			udpAddr, err := net.ResolveUDPAddr("udp", addrStr)
			if err != nil {
				continue
			}
			conn, err := net.ListenUDP("udp", udpAddr)
			if err != nil {
				log.Printf("监听 %s 失败: %v", addrStr, err)
				continue
			}
			conns = append(conns, conn)
			fmt.Println("监听:", conn.LocalAddr())
		}
	}

	if len(conns) == 0 {
		return nil, fmt.Errorf("没有可用的监听地址")
	}
	return conns, nil
}
