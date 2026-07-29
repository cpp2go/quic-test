package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"quic-test/quic"
)

const saveDir = "received_files"

func main() {
	if err := fileServer(); err != nil {
		log.Fatal(err)
	}
}

func fileServer() error {
	// 确保接收目录存在
	if err := os.MkdirAll(saveDir, 0755); err != nil {
		return fmt.Errorf("创建保存目录失败: %w", err)
	}

	// 遍历本机所有网卡 IP 逐一绑定
	udpConns, err := listenAllIPs(4242)
	if err != nil {
		return err
	}

	cfg := &quic.Config{
		CongestionControl: quic.CongestionBBR, // 文件传输建议 BBR，吞吐更好
	}
	listener := quic.ListenAddrs(udpConns, cfg)
	defer listener.Close()

	fmt.Println("文件传输服务器已启动，等待文件上传...")

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			fmt.Println("Accept error:", err)
			return err
		}
		fmt.Printf("新连接: %s -> %s\n", conn.LocalAddr(), conn.RemoteAddr())
		go handleFileConn(conn)
	}
}

const (
	opUpload   = byte(0x01)
	opDownload = byte(0x02)
)

func handleFileConn(conn *quic.Connection) {
	defer conn.CloseWithError(0, "bye")

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			fmt.Println("AcceptStream error:", err)
			return
		}
		go handleStream(stream)
	}
}

func handleStream(stream *quic.Stream) {
	defer stream.Close()

	// 读取操作类型 (1 byte)
	opBuf := make([]byte, 1)
	if _, err := io.ReadFull(stream, opBuf); err != nil {
		fmt.Printf("读取操作类型失败: %v\n", err)
		return
	}

	switch opBuf[0] {
	case opUpload:
		handleUpload(stream)
	case opDownload:
		handleDownload(stream)
	default:
		fmt.Printf("未知操作类型: %d\n", opBuf[0])
	}
}

// 上传协议: [op:1][nameLen:2][fileName][fileSize:8][fileContent...] + FIN
// 回复: ack string
func handleUpload(stream *quic.Stream) {
	start := time.Now()

	// --- 读取文件名长度 ---
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		fmt.Printf("读取文件名长度失败: %v\n", err)
		return
	}
	nameLen := binary.BigEndian.Uint16(lenBuf)

	// --- 读取文件名 ---
	nameBuf := make([]byte, nameLen)
	if _, err := io.ReadFull(stream, nameBuf); err != nil {
		fmt.Printf("读取文件名失败: %v\n", err)
		return
	}
	fileName := string(nameBuf)

	// --- 读取文件大小 ---
	sizeBuf := make([]byte, 8)
	if _, err := io.ReadFull(stream, sizeBuf); err != nil {
		fmt.Printf("读取文件大小失败: %v\n", err)
		return
	}
	fileSize := int64(binary.BigEndian.Uint64(sizeBuf))

	safeName := filepath.Base(fileName)
	savePath := filepath.Join(saveDir, safeName)
	fmt.Printf("[上传] %s (%d 字节) -> %s\n", safeName, fileSize, savePath)

	// --- 创建文件并写入 ---
	f, err := os.Create(savePath)
	if err != nil {
		fmt.Printf("创建文件失败: %v\n", err)
		return
	}
	defer f.Close()

	var totalRecv int64
	buf := make([]byte, 65536)
	progressTicker := time.NewTicker(1 * time.Second)
	defer progressTicker.Stop()

	go func() {
		for range progressTicker.C {
			if totalRecv > 0 {
				pct := float64(totalRecv) / float64(fileSize) * 100
				fmt.Printf("  [上传 %s] %.1f%% (%s/%s)\n",
					safeName, pct, formatSize(totalRecv), formatSize(fileSize))
			}
		}
	}()

	for {
		n, err := stream.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("读取流数据失败: %v\n", err)
			return
		}
		if n > 0 {
			if _, err := f.Write(buf[:n]); err != nil {
				fmt.Printf("写入文件失败: %v\n", err)
				return
			}
			totalRecv += int64(n)
		}
		if totalRecv >= fileSize {
			break // 数据收齐，即使 FIN 丢包也退出
		}
	}

	progressTicker.Stop() // 停止进度打印

	// 发送确认
	ackMsg := fmt.Sprintf("OK: received %s (%d bytes)", safeName, totalRecv)
	stream.Write([]byte(ackMsg))

	elapsed := time.Since(start)
	speed := float64(totalRecv) / elapsed.Seconds()
	fmt.Printf("  ✓ [上传 %s] 完成: %d 字节, %v, %s/s\n",
		safeName, totalRecv, elapsed.Round(time.Millisecond), formatSize(int64(speed)))
}

// 下载协议: [op:1][nameLen:2][fileName] + FIN
// 回复: [fileSize:8][fileContent...] + FIN
func handleDownload(stream *quic.Stream) {
	start := time.Now()

	// --- 读取文件名长度 ---
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		fmt.Printf("读取文件名长度失败: %v\n", err)
		return
	}
	nameLen := binary.BigEndian.Uint16(lenBuf)

	// --- 读取文件名 ---
	nameBuf := make([]byte, nameLen)
	if _, err := io.ReadFull(stream, nameBuf); err != nil {
		fmt.Printf("读取文件名失败: %v\n", err)
		return
	}
	fileName := string(nameBuf)

	// 安全：防目录穿越，只允许访问 saveDir 下的文件
	safeName := filepath.Base(fileName)
	filePath := filepath.Join(saveDir, safeName)

	fmt.Printf("[下载] 请求: %s\n", safeName)

	// --- 打开文件 ---
	f, err := os.Open(filePath)
	if err != nil {
		errMsg := fmt.Sprintf("ERROR: file not found: %s", safeName)
		fmt.Println("  ", errMsg)
		// 先发 fileSize=0 表示错误，再发错误消息
		zero := make([]byte, 8)
		stream.Write(zero)
		stream.Write([]byte(errMsg))
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		errMsg := fmt.Sprintf("ERROR: stat failed: %s", safeName)
		fmt.Println("  ", errMsg)
		zero := make([]byte, 8)
		stream.Write(zero)
		stream.Write([]byte(errMsg))
		return
	}
	fileSize := stat.Size()

	// --- 发送文件大小 (8字节) ---
	sizeBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(sizeBuf, uint64(fileSize))
	if _, err := stream.Write(sizeBuf); err != nil {
		fmt.Printf("发送文件大小失败: %v\n", err)
		return
	}

	fmt.Printf("  发送 %s (%s)...\n", safeName, formatSize(fileSize))

	// --- 发送文件内容 ---
	var totalSent int64
	buf := make([]byte, 65536)
	progressTicker := time.NewTicker(1 * time.Second)
	defer progressTicker.Stop()

	go func() {
		for range progressTicker.C {
			if totalSent > 0 {
				pct := float64(totalSent) / float64(fileSize) * 100
				fmt.Printf("  [下载 %s] %.1f%% (%s/%s)\n",
					safeName, pct, formatSize(totalSent), formatSize(fileSize))
			}
		}
	}()

	for {
		n, err := f.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("读取文件失败: %v\n", err)
			return
		}
		if n == 0 {
			break
		}
		if _, err := stream.Write(buf[:n]); err != nil {
			fmt.Printf("发送数据失败: %v\n", err)
			return
		}
		totalSent += int64(n)
	}

	elapsed := time.Since(start)
	speed := float64(totalSent) / elapsed.Seconds()
	fmt.Printf("  ✓ [下载 %s] 完成: %d 字节, %v, %s/s\n",
		safeName, totalSent, elapsed.Round(time.Millisecond), formatSize(int64(speed)))
}

func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// listenAllIPs 遍历本机所有网卡，对每个 IP 地址尝试绑定 UDP 端口。
func listenAllIPs(port int) ([]*net.UDPConn, error) {
	seen := make(map[string]bool)
	var conns []*net.UDPConn

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("获取网卡列表失败: %w", err)
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
				fmt.Printf("  (监听 %s 失败: %v)\n", addrStr, err)
				continue
			}
			conns = append(conns, conn)
			fmt.Println("文件传输服务器监听:", conn.LocalAddr())
		}
	}

	if len(conns) == 0 {
		return nil, fmt.Errorf("没有可用的监听地址")
	}
	return conns, nil
}
