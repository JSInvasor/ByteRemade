package ui

import (
	"cnc/internal/config"
	"cnc/internal/models"
	"cnc/internal/state"
	"fmt"
	"net"
	"time"
)

const (
	RESET      = "\033[0m"
	RED        = "\033[1;31m"
	GREEN      = "\033[1;32m"
	YELLOW     = "\033[1;33m"
	BLUE       = "\033[1;34m"
	PINK       = "\033[1;35m"
	CYAN       = "\033[1;36m"
	LIGHT_BLUE = "\033[1;34m"
	LIGHT_PINK = "\033[1;95m"
	NEON       = "\033[1;96m"
	WHITE      = "\033[38;5;231m"
	GREY       = "\033[38;5;252m"
	GREY2      = "\033[38;5;254m"
	CLEAR      = "\033[2J\033[1;1H"
)

func UpdateTitle(conn net.Conn, user *models.User) {
	for {
		state.BotMutex.Lock()
		validBots := 0
		uniqueIPs := make(map[string]bool)
		for i := 0; i < state.BotCount; i++ {
			if state.Bots[i].IsValid {
				if _, ok := uniqueIPs[state.Bots[i].Ip]; !ok {
					uniqueIPs[state.Bots[i].Ip] = true
					validBots++
				}
			}
		}
		state.BotMutex.Unlock()

		state.UsersMutex.Lock()
		usersOnline := 0
		for i := 0; i < state.UserCount; i++ {
			if state.Users[i].IsLoggedIn {
				usersOnline++
			}
		}
		state.UsersMutex.Unlock()

		state.CooldownMutex.Lock()
		slotsInUse := state.CurrentGlobalSlots
		state.CooldownMutex.Unlock()

		settings, err := config.ReadSettings()
		maxSlots := settings.MaxGlobalSlots
		if err != nil {
			maxSlots = 0
		}

		title := fmt.Sprintf("\033]0;Bots : %d | Onlines : %d/%d | Slots : %d/%d | Attacks : %d/%d\007", validBots, usersOnline, state.UserCount, slotsInUse, maxSlots, user.DailyUsed, user.DailyLimit)
		_, err = conn.Write([]byte(title))
		if err != nil {
			return
		}

		time.Sleep(2 * time.Second)
	}
}
