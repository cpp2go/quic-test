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

	// 循环发包 10 秒测试
	const duration = 10 * time.Second
	const interval = 100 * time.Millisecond
	buf := make([]byte, 1024)
	sendCount := 0
	recvCount := 0
	start := time.Now()

	fmt.Printf("开始压测 %v，间隔 %v...\n", duration, interval)

	for time.Since(start) < duration {
		msg := fmt.Sprintf("hello %d", sendCount)
		_, err := stream.Write([]byte(msg))
		if err != nil {
			fmt.Println("写入错误:", err)
			break
		}

		stream.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := stream.Read(buf)
		if err != nil && err != io.EOF {
			if err == context.DeadlineExceeded {
				fmt.Println("读取超时")
			} else {
				fmt.Println("读取错误:", err)
			}
			break
		}
		if n > 0 {
			recvCount++
		}
		sendCount++

		// 每秒输出进度
		if sendCount%10 == 0 {
			fmt.Printf("  [%ds] 发送 %d / 接收 %d\n",
				int(time.Since(start).Seconds()), sendCount, recvCount)
		}
	}

	elapsed := time.Since(start)
	fmt.Printf("\n测试完成: 耗时 %v\n", elapsed)
	fmt.Printf("发送: %d 包, 接收: %d 包\n", sendCount, recvCount)
	fmt.Printf("吞吐: %.0f pkt/s\n", float64(sendCount)/elapsed.Seconds())

	fmt.Println("测试完成!")
}
