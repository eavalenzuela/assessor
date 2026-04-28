package sysfacts

import (
	"bufio"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/t3rmit3/assessor/internal/finding"
)

type Facts struct {
	Host           finding.HostInfo
	OSReleaseID    string
	OSReleaseVer   string
	HasSystemd     bool
	HasIptables    bool
	HasNftables    bool
	HasUFW         bool
	HasFirewalld   bool
	HasSELinux     bool
	HasAppArmor    bool
	HasDocker      bool
	HasPodman      bool
	PackageManager string
}

func Gather(version string) Facts {
	f := Facts{}
	f.Host.AssessorVer = version
	f.Host.Arch = runtime.GOARCH
	if h, err := os.Hostname(); err == nil {
		f.Host.Hostname = h
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		f.Host.KernelRel = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/etc/machine-id"); err == nil {
		f.Host.MachineID = strings.TrimSpace(string(b))
	}
	parseOSRelease(&f)
	detectTooling(&f)
	return f
}

func parseOSRelease(f *Facts) {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return
	}
	defer file.Close()
	s := bufio.NewScanner(file)
	for s.Scan() {
		line := s.Text()
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "ID":
			f.OSReleaseID = v
		case "VERSION_ID":
			f.OSReleaseVer = v
		case "PRETTY_NAME":
			f.Host.Distro = v
		}
	}
}

func detectTooling(f *Facts) {
	has := func(bin string) bool { _, err := exec.LookPath(bin); return err == nil }
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		f.HasSystemd = true
	}
	f.HasIptables = has("iptables")
	f.HasNftables = has("nft")
	f.HasUFW = has("ufw")
	f.HasFirewalld = has("firewall-cmd")
	if _, err := os.Stat("/sys/fs/selinux"); err == nil {
		f.HasSELinux = true
	}
	if _, err := os.Stat("/sys/kernel/security/apparmor"); err == nil {
		f.HasAppArmor = true
	}
	f.HasDocker = has("docker")
	f.HasPodman = has("podman")
	switch {
	case has("apt"):
		f.PackageManager = "apt"
	case has("dnf"):
		f.PackageManager = "dnf"
	case has("yum"):
		f.PackageManager = "yum"
	case has("pacman"):
		f.PackageManager = "pacman"
	case has("apk"):
		f.PackageManager = "apk"
	case has("zypper"):
		f.PackageManager = "zypper"
	}
}
