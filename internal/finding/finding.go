package finding

import "time"

type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

type Status string

const (
	StatusPass       Status = "pass"
	StatusFail       Status = "fail"
	StatusWarn       Status = "warn"
	StatusSkipped    Status = "skipped"
	StatusUnverified Status = "unverified"
	StatusError      Status = "error"
)

type Reference struct {
	Source string `json:"source"`
	ID     string `json:"id"`
	URL    string `json:"url,omitempty"`
}

type Evidence struct {
	Kind    string `json:"kind"`
	Source  string `json:"source"`
	Content string `json:"content"`
	Line    int    `json:"line,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
}

type Remediation struct {
	Description string   `json:"description"`
	Commands    []string `json:"commands,omitempty"`
}

type Metadata struct {
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	Bucket      string      `json:"bucket"`
	Severity    Severity    `json:"severity"`
	Description string      `json:"description"`
	Refs        []Reference `json:"refs,omitempty"`
	Profiles    []string    `json:"profiles,omitempty"`
	RequiresCmd []string    `json:"requires_cmd,omitempty"`
}

type Finding struct {
	Meta        Metadata    `json:"meta"`
	Status      Status      `json:"status"`
	Message     string      `json:"message,omitempty"`
	Evidence    []Evidence  `json:"evidence,omitempty"`
	Remediation Remediation `json:"remediation,omitempty"`
	StartedAt   time.Time   `json:"started_at"`
	Duration    string      `json:"duration"`
	Err         string      `json:"error,omitempty"`
}

type Report struct {
	Host       HostInfo  `json:"host"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Profile    string    `json:"profile"`
	Findings   []Finding `json:"findings"`
	Summary    Summary   `json:"summary"`
}

type HostInfo struct {
	Hostname    string `json:"hostname"`
	Distro      string `json:"distro"`
	KernelRel   string `json:"kernel_release"`
	Arch        string `json:"arch"`
	BootID      string `json:"boot_id,omitempty"`
	MachineID   string `json:"machine_id,omitempty"`
	Virt        string `json:"virtualization,omitempty"`
	Container   string `json:"container,omitempty"`
	AssessorVer string `json:"assessor_version"`
}

type Summary struct {
	Total      int            `json:"total"`
	ByStatus   map[Status]int `json:"by_status"`
	BySeverity map[Severity]int `json:"by_severity"`
	RiskScore  int            `json:"risk_score"`
}
