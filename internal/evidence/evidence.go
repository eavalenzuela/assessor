package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/t3rmit3/assessor/internal/finding"
)

const maxCapture = 64 * 1024

func File(path string) (finding.Evidence, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return finding.Evidence{}, err
	}
	sum := sha256.Sum256(b)
	content := string(b)
	if len(content) > maxCapture {
		content = content[:maxCapture] + "\n...[truncated]"
	}
	return finding.Evidence{
		Kind:    "file",
		Source:  path,
		Content: content,
		SHA256:  hex.EncodeToString(sum[:]),
	}, nil
}

func FileLine(path string, line int, contents string) finding.Evidence {
	return finding.Evidence{
		Kind:    "file_line",
		Source:  fmt.Sprintf("%s:%d", path, line),
		Line:    line,
		Content: contents,
	}
}

func Command(name string, args ...string) (finding.Evidence, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	content := string(out)
	if len(content) > maxCapture {
		content = content[:maxCapture] + "\n...[truncated]"
	}
	ev := finding.Evidence{
		Kind:    "command",
		Source:  strings.Join(append([]string{name}, args...), " "),
		Content: content,
	}
	return ev, err
}

func Note(source, content string) finding.Evidence {
	return finding.Evidence{Kind: "note", Source: source, Content: content}
}
