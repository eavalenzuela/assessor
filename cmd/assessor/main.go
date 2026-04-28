package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/t3rmit3/assessor/internal/baseline"
	"github.com/t3rmit3/assessor/internal/cve"
	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/profiles"
	jsonout "github.com/t3rmit3/assessor/internal/report/json"
	"github.com/t3rmit3/assessor/internal/report/pdf"
	"github.com/t3rmit3/assessor/internal/report/tty"

	// Side-effect imports register checks into the engine.
	_ "github.com/t3rmit3/assessor/checks/auth"
	_ "github.com/t3rmit3/assessor/checks/containers"
	_ "github.com/t3rmit3/assessor/checks/cron"
	_ "github.com/t3rmit3/assessor/checks/crypto"
	_ "github.com/t3rmit3/assessor/checks/forensic"
	_ "github.com/t3rmit3/assessor/checks/fs"
	_ "github.com/t3rmit3/assessor/checks/kernel"
	_ "github.com/t3rmit3/assessor/checks/logging"
	_ "github.com/t3rmit3/assessor/checks/mac"
	_ "github.com/t3rmit3/assessor/checks/network"
	pkgChecks "github.com/t3rmit3/assessor/checks/packages"
	_ "github.com/t3rmit3/assessor/checks/services"
	_ "github.com/t3rmit3/assessor/checks/ssh"
	_ "github.com/t3rmit3/assessor/checks/time"
	_ "github.com/t3rmit3/assessor/checks/webdb"
)

const version = "0.1.0-dev"

func main() {
	root := &cobra.Command{
		Use:   "assessor",
		Short: "Comprehensive Linux system assessment",
		Long:  "assessor inspects a running Linux host for security and configuration issues with evidence-first reporting.",
	}
	root.AddCommand(runCmd(), listCmd(), diffCmd(), cveCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runCmd() *cobra.Command {
	var (
		profile     string
		buckets     []string
		ids         []string
		parallel    int
		outJSON     string
		outPDF      string
		cveDB       string
		saveSnap    bool
		snapDir     string
		quietTTY    bool
		skipRoot    bool
		profileDir  string
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run all (or filtered) checks and emit a report",
		RunE: func(c *cobra.Command, args []string) error {
			if !skipRoot {
				if err := engine.RequireRoot(); err != nil {
					return err
				}
			}
			if cveDB != "" {
				db := cve.NewDB()
				if err := db.LoadCache(cveDB); err != nil {
					return fmt.Errorf("loading CVE db %s: %w", cveDB, err)
				}
				pkgChecks.SetDB(db)
			}
			ctx := context.Background()
			profileDef, err := profiles.Load(profileDir, profile)
			if err != nil {
				return err
			}
			report, err := engine.Run(ctx, engine.Options{
				Profile:     profile,
				ProfileDef:  profileDef,
				Buckets:     buckets,
				IDs:         ids,
				Parallelism: parallel,
				Version:     version,
			})
			if err != nil {
				return err
			}
			if !quietTTY {
				if err := tty.Write(os.Stdout, report); err != nil {
					return err
				}
			}
			if outJSON != "" {
				f, err := os.Create(outJSON)
				if err != nil {
					return err
				}
				defer f.Close()
				if err := jsonout.Write(f, report); err != nil {
					return err
				}
			}
			if outPDF != "" {
				if err := pdf.Write(outPDF, report); err != nil {
					return err
				}
			}
			if saveSnap {
				path, err := baseline.Save(snapDir, report)
				if err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "snapshot saved: %s\n", path)
			}
			if report.Summary.ByStatus[finding.StatusFail] > 0 {
				os.Exit(2)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&profile, "profile", "server", "profile filter (server, workstation, cis-l1, ...)")
	cmd.Flags().StringSliceVar(&buckets, "bucket", nil, "limit to bucket(s)")
	cmd.Flags().StringSliceVar(&ids, "id", nil, "limit to check id(s)")
	cmd.Flags().IntVar(&parallel, "parallel", 8, "max concurrent checks")
	cmd.Flags().StringVar(&outJSON, "json", "", "write JSON report to path")
	cmd.Flags().StringVar(&outPDF, "pdf", "", "write PDF report to path")
	cmd.Flags().StringVar(&cveDB, "cve-db", "", "path to cached CVE feed JSON")
	cmd.Flags().BoolVar(&saveSnap, "snapshot", false, "save report as a baseline snapshot")
	cmd.Flags().StringVar(&snapDir, "snapshot-dir", baseline.DefaultDir, "snapshot directory")
	cmd.Flags().BoolVar(&quietTTY, "quiet", false, "suppress TTY output")
	cmd.Flags().BoolVar(&skipRoot, "skip-root-check", false, "permit non-root run (debug only)")
	cmd.Flags().StringVar(&profileDir, "profile-dir", "profiles", "directory containing profile YAML files")
	return cmd
}

func listCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List registered checks",
		RunE: func(c *cobra.Command, args []string) error {
			for _, ck := range engine.All() {
				m := ck.Meta()
				fmt.Printf("%-40s [%s]  %s — %s  (%s)\n",
					m.ID, m.Severity, m.Bucket, m.Title, strings.Join(m.Profiles, ","))
			}
			return nil
		},
	}
}

func diffCmd() *cobra.Command {
	var (
		prevPath  string
		asJSON    bool
		skipRoot  bool
	)
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Run checks now and diff against the latest snapshot",
		RunE: func(c *cobra.Command, args []string) error {
			if !skipRoot {
				if err := engine.RequireRoot(); err != nil {
					return err
				}
			}
			if prevPath == "" {
				p, err := baseline.Latest("")
				if err != nil {
					return err
				}
				prevPath = p
			}
			prev, err := baseline.Load(prevPath)
			if err != nil {
				return err
			}
			cur, err := engine.Run(context.Background(), engine.Options{Version: version})
			if err != nil {
				return err
			}
			d := baseline.Compare(prev, cur)
			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(d)
			}
			baseline.RenderTTY(os.Stdout, prevPath, prev, cur, d)
			return nil
		},
	}
	cmd.Flags().StringVar(&prevPath, "previous", "", "path to previous snapshot (default: newest in /var/lib/assessor)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit machine-readable JSON instead of TTY output")
	cmd.Flags().BoolVar(&skipRoot, "skip-root-check", false, "permit non-root run (debug only)")
	return cmd
}

func cveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cve",
		Short: "Manage CVE feed cache",
	}
	var out string
	sync := &cobra.Command{
		Use:   "sync",
		Short: "Sync NVD into a local cache file (paginated, slow without API key)",
		RunE: func(c *cobra.Command, args []string) error {
			db := cve.NewDB()
			n := &cve.NVDDownloader{APIKey: os.Getenv("NVD_API_KEY")}
			start := 0
			for {
				vs, total, err := n.FetchPage(start)
				if err != nil {
					return err
				}
				for _, v := range vs {
					db.Add(v)
				}
				start += len(vs)
				fmt.Fprintf(os.Stderr, "fetched %d / %d\n", start, total)
				if start >= total || len(vs) == 0 {
					break
				}
			}
			return db.SaveCache(out)
		},
	}
	sync.Flags().StringVar(&out, "out", "/var/lib/assessor/cve.json", "cache output path")
	cmd.AddCommand(sync)
	return cmd
}
