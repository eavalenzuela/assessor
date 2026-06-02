package webdb

import (
	"bufio"
	"context"
	"fmt"
	"io"
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
		status, msg := evaluateRedis(cfg)
		out := finding.Finding{Status: status, Message: msg, Evidence: []finding.Evidence{ev}}
		if status == finding.StatusFail {
			out.Remediation = finding.Remediation{
				Description: "Bind to 127.0.0.1, or set protected-mode yes AND a strong requirepass.",
			}
		}
		return out
	}
	return finding.Finding{Status: finding.StatusSkipped, Message: "no redis config found"}
}

// evaluateRedis decides whether a parsed redis config exposes the server
// unsafely. A redis bound to a non-loopback address is a Fail unless it has
// BOTH protected-mode yes AND a requirepass; loopback-only (or unset bind) is
// always a Pass.
func evaluateRedis(cfg map[string]string) (finding.Status, string) {
	bind := cfg["bind"]
	protected := strings.ToLower(cfg["protected-mode"])
	requirepass := cfg["requirepass"]
	boundExternal := bind != "" && !isLoopbackOnly(bind)
	if boundExternal && (requirepass == "" || protected != "yes") {
		return finding.StatusFail, fmt.Sprintf("redis bind=%q requirepass=%q protected-mode=%q", bind, requirepass, protected)
	}
	return finding.StatusPass, "redis config OK"
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
		status, msg := evaluateMysqlBind(bind)
		out := finding.Finding{Status: status, Message: msg, Evidence: []finding.Evidence{ev}}
		if status == finding.StatusWarn {
			out.Remediation = finding.Remediation{
				Commands: []string{"echo 'bind-address = 127.0.0.1' >> " + p, "systemctl restart mariadb"},
			}
		}
		return out
	}
	return finding.Finding{Status: finding.StatusSkipped, Message: "no MySQL/MariaDB config found"}
}

// evaluateMysqlBind classifies a MySQL/MariaDB bind-address value: unset is a
// Warn (the default may be 0.0.0.0), an explicit all-interfaces value is a
// Fail, and anything else (a specific address) passes.
func evaluateMysqlBind(bind string) (finding.Status, string) {
	switch bind {
	case "":
		return finding.StatusWarn, "bind-address not set; default may be 0.0.0.0"
	case "0.0.0.0", "::":
		return finding.StatusFail, "bind-address listens on all interfaces"
	default:
		return finding.StatusPass, "bind-address=" + bind
	}
}

func simpleKV(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseKV(f), nil
}

// parseKV reads space-separated `key value` config lines (redis style),
// skipping blanks and #-comments and stripping surrounding quotes from values.
func parseKV(r io.Reader) map[string]string {
	m := map[string]string{}
	s := bufio.NewScanner(r)
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
	return m
}

func iniValue(path, key string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	return parseINIValue(f, key)
}

// parseINIValue returns the first `key = value` match (case-insensitive key)
// from INI-style content, skipping blanks and #/; comments. Returns "" if the
// key is absent.
func parseINIValue(r io.Reader, key string) string {
	s := bufio.NewScanner(r)
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
