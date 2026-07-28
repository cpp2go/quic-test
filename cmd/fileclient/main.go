package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"quic-test/quic"
)

const (
	opUpload   = byte(0x01)
	opDownload = byte(0x02)
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("用法:")
		fmt.Println("  上传: fileclient upload <本地文件路径>")
		fmt.Println("  下载: fileclient download <远程文件名> [保存路径]")
		fmt.Println("示例:")
		fmt.Println("  fileclient upload ./example.mp4")
		fmt.Println("  fileclient download example.mp4")
		fmt.Println("  fileclient download example.mp4 ./mycopy.mp4")
		os.Exit(1)
	}

	mode := strings.ToLower(os.Args[1])

	switch mode {
	case "upload":
		if len(os.Args) < 3 {
			log.Fatal("请指定要上传的文件路径")
		}
		if err := uploadFile(os.Args[2]); err != nil {
			log.Fatal(err)
		}
	case "download":
		if len(os.Args) < 3 {
			log.Fatal("请指定要下载的文件名")
		}
		savePath := ""
		if len(os.Args) >= 4 {
			savePath = os.Args[3]
		}
		if err := downloadFile(os.Args[2], savePath); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("未知模式: %s (可用: upload / download)", mode)
	}
}

// ---- 连接复用 ----

func dialServer() (*quic.Connection, error) {
	cfg := &quic.Config{
		CongestionControl: quic.CongestionBBR,
	}
	addrs := []string{"[::1]:4242", "127.0.0.1:4242"}
	fmt.Printf("连接服务器 %v ...\n", addrs)

	conn, err := quic.DialHappy(context.Background(), addrs, cfg)
	if err != nil {
		return nil, fmt.Errorf("连接失败: %w", err)
	}
	fmt.Println("连接成功:", conn.LocalAddr(), "->", conn.RemoteAddr())
	return conn, nil
}

// ---- 上传 ----

func uploadFile(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("打开文件失败: %w", err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return fmt.Errorf("获取文件信息失败: %w", err)
	}
	fileSize := stat.Size()
	fileName := filepath.Base(filePath)

	fmt.Printf("准备上传: %s (%s)\n", fileName, formatSize(fileSize))

	conn, err := dialServer()
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "bye")

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return fmt.Errorf("打开流失败: %w", err)
	}
	defer stream.Close()
	fmt.Println("流已打开, ID:", stream.StreamID())

	// --- 构造请求: [op:1][nameLen:2][fileName][fileSize:8] ---
	nameBuf := []byte(fileName)
	if len(nameBuf) > 65535 {
		return fmt.Errorf("文件名过长")
	}

	header := []byte{opUpload}
	header = binary.BigEndian.AppendUint16(header, uint16(len(nameBuf)))
	header = append(header, nameBuf...)
	header = binary.BigEndian.AppendUint64(header, uint64(fileSize))

	if _, err := stream.Write(header); err != nil {
		return fmt.Errorf("发送文件头失败: %w", err)
	}

	// --- 发送文件内容 ---
	start := time.Now()
	var totalSent int64
	buf := make([]byte, 65536)
	progressTicker := time.NewTicker(1 * time.Second)
	defer progressTicker.Stop()

	go func() {
		for range progressTicker.C {
			if totalSent > 0 {
				pct := float64(totalSent) / float64(fileSize) * 100
				fmt.Printf("  [上传] %.1f%% (%s/%s)\n",
					pct, formatSize(totalSent), formatSize(fileSize))
			}
		}
	}()

	for {
		n, err := f.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取文件失败: %w", err)
		}
		if n == 0 {
			break
		}
		if _, err := stream.Write(buf[:n]); err != nil {
			return fmt.Errorf("发送数据失败: %w", err)
		}
		totalSent += int64(n)
	}

	// 关闭写入端，等待确认
	stream.Close()

	ackBuf := make([]byte, 4096)
	stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := stream.Read(ackBuf)
	if err != nil && err != io.EOF {
		fmt.Println("(等待确认超时)")
	} else if n > 0 {
		fmt.Printf("服务器确认: %s\n", string(ackBuf[:n]))
	}

	elapsed := time.Since(start)
	speed := float64(totalSent) / elapsed.Seconds()
	fmt.Printf("\n✓ 上传完成!\n")
	fmt.Printf("  文件: %s\n", fileName)
	fmt.Printf("  大小: %s\n", formatSize(fileSize))
	fmt.Printf("  耗时: %v\n", elapsed.Round(time.Millisecond))
	fmt.Printf("  速度: %s/s\n", formatSize(int64(speed)))
	return nil
}

// ---- 下载 ----

func downloadFile(remoteName, savePath string) error {
	if savePath == "" {
		savePath = filepath.Base(remoteName)
	}

	fmt.Printf("准备下载: %s -> %s\n", remoteName, savePath)

	conn, err := dialServer()
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "bye")

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return fmt.Errorf("打开流失败: %w", err)
	}
	defer stream.Close()
	fmt.Println("流已打开, ID:", stream.StreamID())

	// --- 发送下载请求: [op:1][nameLen:2][fileName] ---
	nameBuf := []byte(remoteName)
	if len(nameBuf) > 65535 {
		return fmt.Errorf("文件名过长")
	}

	req := []byte{opDownload}
	req = binary.BigEndian.AppendUint16(req, uint16(len(nameBuf)))
	req = append(req, nameBuf...)

	if _, err := stream.Write(req); err != nil {
		return fmt.Errorf("发送下载请求失败: %w", err)
	}

	// 关闭写入端，表示请求结束
	stream.Close()

	// --- 读取响应: 先读 8 字节文件大小 ---
	sizeBuf := make([]byte, 8)
	if _, err := io.ReadFull(stream, sizeBuf); err != nil {
		return fmt.Errorf("读取文件大小失败: %w", err)
	}
	fileSize := int64(binary.BigEndian.Uint64(sizeBuf))

	// 检查是否为错误消息
	if fileSize == 0 {
		errBuf := make([]byte, 4096)
		n, _ := stream.Read(errBuf)
		if n > 0 {
			return fmt.Errorf("服务器错误: %s", string(errBuf[:n]))
		}
	}

	fmt.Printf("开始下载: %s (%s)\n", remoteName, formatSize(fileSize))

	// --- 创建本地文件 ---
	f, err := os.Create(savePath)
	if err != nil {
		return fmt.Errorf("创建文件失败: %w", err)
	}
	defer f.Close()

	// --- 接收文件内容 ---
	start := time.Now()
	var totalRecv int64
	buf := make([]byte, 65536)
	progressTicker := time.NewTicker(1 * time.Second)
	defer progressTicker.Stop()

	go func() {
		for range progressTicker.C {
			if totalRecv > 0 {
				pct := float64(totalRecv) / float64(fileSize) * 100
				fmt.Printf("  [下载] %.1f%% (%s/%s)\n",
					pct, formatSize(totalRecv), formatSize(fileSize))
			}
		}
	}()

	for {
		n, err := stream.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("接收数据失败: %w", err)
		}
		if n == 0 {
			break
		}
		if _, err := f.Write(buf[:n]); err != nil {
			return fmt.Errorf("写入文件失败: %w", err)
		}
		totalRecv += int64(n)
	}

	elapsed := time.Since(start)
	speed := float64(totalRecv) / elapsed.Seconds()
	fmt.Printf("\n✓ 下载完成!\n")
	fmt.Printf("  保存到: %s\n", savePath)
	fmt.Printf("  大小: %s\n", formatSize(totalRecv))
	fmt.Printf("  耗时: %v\n", elapsed.Round(time.Millisecond))
	fmt.Printf("  速度: %s/s\n", formatSize(int64(speed)))
	return nil
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
