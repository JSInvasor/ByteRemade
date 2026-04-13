package util

import (
	"cnc/internal/models"
	"math/rand"
	"time"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var Users []models.User

func GenerateRandomString(length int) string {
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func CheckAPIKey(user, apikey string) bool {
	return user == apikey
}

func ApiAccess(username string) bool {
	for _, u := range Users {
		if u.User == username {
			return u.ApiAccess
		}
	}
	return false
}