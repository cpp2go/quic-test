package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"time"

	"quic-test/quic"
)

func main() {
	// 选择拥塞控制算法: CUBIC / BBR / NewReno
	cfg := &quic.Config{
		CongestionControl: quic.CongestionBBR,
	}

	// Happy Eyeballs: 优先 IPv6，300ms 超时后并发 IPv4
	addrs := []string{"[::1]:4242", "127.0.0.1:4242"}
	fmt.Printf("Happy Eyeballs: 尝试 %v (算法: %s)\n", addrs, cfg.CongestionControl)

	conn, err := quic.DialHappy(context.Background(), addrs, cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.CloseWithError(0, "bye")

	fmt.Println("连接成功:", conn.LocalAddr(), "->", conn.RemoteAddr())

	// 打开一个流
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer stream.Close()

	fmt.Println("流已打开, ID:", stream.StreamID())

	// 发送消息
	msg := "Hello, Pure QUIC!"
	_, err = stream.Write([]byte(msg))
	if err != nil {
		log.Fatal("写入错误:", err)
	}
	fmt.Println("发送:", msg)

	// 读取回显
	buf := make([]byte, 1024)
	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		log.Fatal("读取错误:", err)
	}
	fmt.Printf("收到回显: %s, %d 字节\n", string(buf[:n]), n)

	fmt.Println("测试完成!")
}
