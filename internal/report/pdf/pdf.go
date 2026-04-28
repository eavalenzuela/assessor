package pdf

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/t3rmit3/assessor/internal/finding"
)

// Write renders the report to PDF. It tries Chrome/Chromium headless first
// (best-looking output) and falls back to a wkhtmltopdf invocation. If neither
// tool is available the function returns an error so the caller can choose to
// emit JSON/HTML instead — we avoid bundling gofpdf at this stage to keep the
// dep tree clean while the renderer choice is still in flux.
func Write(out string, r finding.Report) error {
	html, err := renderHTML(r)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp("", "assessor-*.html")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(html); err != nil {
		return err
	}
	tmp.Close()

	if bin := findChrome(); bin != "" {
		return runChrome(bin, tmp.Name(), out)
	}
	if bin, err := exec.LookPath("wkhtmltopdf"); err == nil {
		cmd := exec.Command(bin, "--quiet", tmp.Name(), out)
		return cmd.Run()
	}
	return fmt.Errorf("no PDF renderer found: install chromium, google-chrome, or wkhtmltopdf")
}

func findChrome() string {
	for _, name := range []string{"google-chrome", "chromium", "chromium-browser", "chrome"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

func runChrome(bin, htmlPath, outPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin,
		"--headless=new",
		"--disable-gpu",
		"--no-sandbox",
		"--no-pdf-header-footer",
		"--print-to-pdf="+outPath,
		"file://"+htmlPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("chrome: %w: %s", err, string(out))
	}
	return nil
}

func renderHTML(r finding.Report) ([]byte, error) {
	t, err := template.New("report").Funcs(template.FuncMap{
		"upper": strings.ToUpper,
		"sevClass": func(s finding.Severity) string {
			return "sev-" + string(s)
		},
		"statusClass": func(s finding.Status) string {
			return "status-" + string(s)
		},
	}).Parse(htmlTpl)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

const htmlTpl = `<!doctype html>
<html><head><meta charset="utf-8"><title>Assessor Report — {{.Host.Hostname}}</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; color: #111; margin: 32px; }
  h1 { margin: 0 0 4px 0; }
  .meta { color: #555; font-size: 12px; margin-bottom: 24px; }
  .summary { display: flex; gap: 16px; margin-bottom: 24px; }
  .summary div { padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; }
  .finding { border: 1px solid #e3e3e3; border-radius: 8px; padding: 12px 16px; margin-bottom: 12px; page-break-inside: avoid; }
  .finding h3 { margin: 0 0 4px 0; font-size: 14px; }
  .badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; margin-right: 6px; }
  .status-pass { background: #d4edda; color: #155724; }
  .status-fail { background: #f8d7da; color: #721c24; }
  .status-warn { background: #fff3cd; color: #856404; }
  .status-unverified, .status-skipped { background: #e2e3e5; color: #383d41; }
  .status-error { background: #d6d8db; color: #1b1e21; }
  .sev-critical { background: #6f42c1; color: white; }
  .sev-high { background: #dc3545; color: white; }
  .sev-medium { background: #fd7e14; color: white; }
  .sev-low { background: #007bff; color: white; }
  .sev-info { background: #6c757d; color: white; }
  .evidence { background: #f6f8fa; border-left: 3px solid #999; padding: 8px 10px; margin: 6px 0; font-family: ui-monospace, Menlo, monospace; font-size: 11px; white-space: pre-wrap; }
  .src { color: #555; font-size: 11px; }
  .fix { color: #155724; margin-top: 6px; }
</style></head>
<body>
<h1>Assessor Report</h1>
<div class="meta">
  Host: <b>{{.Host.Hostname}}</b> · {{.Host.Distro}} · kernel {{.Host.KernelRel}} · {{.Host.Arch}}<br>
  Profile: {{.Profile}} · Generated: {{.StartedAt.Format "2006-01-02 15:04:05 MST"}}
</div>
<div class="summary">
  <div>Total: <b>{{.Summary.Total}}</b></div>
  <div>Risk: <b>{{.Summary.RiskScore}}</b></div>
  {{range $k, $v := .Summary.ByStatus}}<div>{{$k}}: <b>{{$v}}</b></div>{{end}}
</div>
{{range .Findings}}
<div class="finding">
  <h3>
    <span class="badge {{statusClass .Status}}">{{upper (printf "%s" .Status)}}</span>
    <span class="badge {{sevClass .Meta.Severity}}">{{upper (printf "%s" .Meta.Severity)}}</span>
    <code>{{.Meta.ID}}</code> — {{.Meta.Title}}
  </h3>
  {{if .Message}}<div>{{.Message}}</div>{{end}}
  {{range .Evidence}}
    <div class="src">↳ {{.Source}}</div>
    <pre class="evidence">{{.Content}}</pre>
  {{end}}
  {{if .Remediation.Description}}
    <div class="fix"><b>Fix:</b> {{.Remediation.Description}}</div>
    {{range .Remediation.Commands}}<div class="fix"><code>$ {{.}}</code></div>{{end}}
  {{end}}
</div>
{{end}}
</body></html>`
