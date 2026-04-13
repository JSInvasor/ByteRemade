package models

import "net"

const MAX_BOTS = 6500
const MAX_USERS = 8

type Bot struct {
	Conn    net.Conn
	IsValid bool
	Arch    string
	Ip      string
}

type User struct {
	User          string `json:"user"`
	Pass          string `json:"pass"`
	MaxTime       int    `json:"maxTime"`
	MaxBots       int    `json:"maxBots"`
	MaxSlots      int    `json:"maxSlots"`
	IsLoggedIn    bool   `json:"-"`
	CurrentSlots  int    `json:"-"`
	IsAdmin       bool   `json:"isAdmin"`
	DailyLimit    int    `json:"dailyLimit"`
	DailyUsed     int    `json:"dailyUsed"`
	LastResetDate string `json:"lastResetDate"`
	ApiAccess     bool   `json:"apiAccess"`
	ApiKey        string `json:"apiKey"`
}

type Settings struct {
	GlobalStopAll     bool   `json:"globalStopAll"`
	GlobalUserCommand bool   `json:"globalUserCommand"`
	RootUser          string `json:"rootUser"`
	MaxGlobalSlots    int    `json:"maxGlobalSlots"`
	BotsPassword      string `json:"BotsPassword"`
}

type LogSettings struct {
	FileLogs bool `json:"fileLogs"`
	LogIPs   bool `json:"logIPs"`
}

type BlacklistConfig struct {
	BlacklistedIPs []string `json:"blacklistedIPs"`
}
