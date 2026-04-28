package webdb

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type redisCheck struct{}

func (redisCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "webdb.redis.bind_protected",
		Title:    "Redis binds to loopback or has requirepass + protected-mode",
		Bucket:   "webdb",
		Severity: finding.SevHigh,
	}
}

func (redisCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	for _, p := range []string{"/etc/redis/redis.conf", "/etc/redis.conf"} {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		cfg, err := simpleKV(p)
		if err != nil {
			return finding.Finding{Status: finding.StatusError, Err: err.Error()}
		}
		ev, _ := evidence.File(p)
		bind := cfg["bind"]
		protected := strings.ToLower(cfg["protected-mode"])
		requirepass := cfg["requirepass"]
		boundExternal := bind != "" && !isLoopbackOnly(bind)
		if boundExternal && (requirepass == "" || protected != "yes") {
			return finding.Finding{
				Status:   finding.StatusFail,
				Message:  fmt.Sprintf("redis bind=%q requirepass=%q protected-mode=%q", bind, requirepass, protected),
				Evidence: []finding.Evidence{ev},
				Remediation: finding.Remediation{
					Description: "Bind to 127.0.0.1, or set protected-mode yes AND a strong requirepass.",
				},
			}
		}
		return finding.Finding{Status: finding.StatusPass, Message: "redis config OK", Evidence: []finding.Evidence{ev}}
	}
	return finding.Finding{Status: finding.StatusSkipped, Message: "no redis config found"}
}

func isLoopbackOnly(bind string) bool {
	for _, host := range strings.Fields(bind) {
		if host != "127.0.0.1" && host != "::1" {
			return false
		}
	}
	return true
}

type mysqlBindCheck struct{}

func (mysqlBindCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "webdb.mysql.bind_address",
		Title:    "MySQL/MariaDB bind-address is restricted",
		Bucket:   "webdb",
		Severity: finding.SevHigh,
	}
}

func (mysqlBindCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	candidates := []string{
		"/etc/mysql/mariadb.conf.d/50-server.cnf",
		"/etc/mysql/my.cnf",
		"/etc/my.cnf",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		bind := iniValue(p, "bind-address")
		ev, _ := evidence.File(p)
		if bind == "" {
			return finding.Finding{
				Status:   finding.StatusWarn,
				Message:  "bind-address not set; default may be 0.0.0.0",
				Evidence: []finding.Evidence{ev},
				Remediation: finding.Remediation{
					Commands: []string{"echo 'bind-address = 127.0.0.1' >> " + p, "systemctl restart mariadb"},
				},
			}
		}
		if bind == "0.0.0.0" || bind == "::" {
			return finding.Finding{
				Status:   finding.StatusFail,
				Message:  "bind-address listens on all interfaces",
				Evidence: []finding.Evidence{ev},
			}
		}
		return finding.Finding{Status: finding.StatusPass, Message: "bind-address=" + bind, Evidence: []finding.Evidence{ev}}
	}
	return finding.Finding{Status: finding.StatusSkipped, Message: "no MySQL/MariaDB config found"}
}

func simpleKV(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := map[string]string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			m[fields[0]] = strings.Trim(strings.Join(fields[1:], " "), `"`)
		}
	}
	return m, nil
}

func iniValue(path, key string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), key) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func init() {
	engine.Register(redisCheck{})
	engine.Register(mysqlBindCheck{})
}
