package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/Alfredooe/aurdit/internal/audit"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "check":
		cmdCheck()
	case "help", "-h", "--help":
		usage()
	default:
		cmdAudit(cmd)
	}
}

func cmdAudit(pkg string) {
	history := 5
	skillsDir := "./skills"
	verbose := false
	jsonOut := false
	commit := ""

	// Parse remaining flags after the package name
	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--history":
			if i+1 < len(args) {
				history, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "--skills-dir":
			if i+1 < len(args) {
				skillsDir = args[i+1]
				i++
			}
		case "--commit":
			if i+1 < len(args) {
				commit = args[i+1]
				i++
			}
		case "--json":
			jsonOut = true
		case "-v", "--verbose":
			verbose = true
		}
	}
	if history < 2 {
		history = 2
	}

	apiKey := audit.APIKey()
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "error: DEEPSEEK_API_KEY not set")
		os.Exit(1)
	}

	a := audit.New(apiKey, skillsDir, loadConfig())
	if verbose {
		a.Verbose(os.Stderr)
	}
	ctx := context.Background()

	var result *audit.PackageResult
	var err error
	if commit != "" {
		result, err = a.AuditCommit(ctx, pkg, commit, history)
	} else {
		result, err = a.AuditHistory(ctx, pkg, history)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if jsonOut {
		printResultJSON(result)
	} else {
		printResult(result)
	}
}

func cmdCheck() {
	skillsDir := "./skills"
	verbose := false
	jsonOut := false
	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		if args[i] == "--skills-dir" && i+1 < len(args) {
			skillsDir = args[i+1]
			i++
		} else if args[i] == "-v" || args[i] == "--verbose" {
			verbose = true
		} else if args[i] == "--json" {
			jsonOut = true
		}
	}

	apiKey := audit.APIKey()
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "error: DEEPSEEK_API_KEY not set")
		os.Exit(1)
	}

	updates, err := audit.ListUpdates()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if len(updates) == 0 {
		if !jsonOut {
			fmt.Println("No AUR packages with pending updates found.")
		}
		return
	}

	if !jsonOut {
		fmt.Printf("\nFound %d package(s) with pending updates:\n", len(updates))
		for _, u := range updates {
			fmt.Printf("  %s  %s → %s\n", u.Name, u.InstalledVersion, u.AURVersion)
		}
		fmt.Println()
	}

	a := audit.New(apiKey, skillsDir, loadConfig())
	if verbose {
		a.Verbose(os.Stderr)
	}

	progress := func(pkg, verdict string) {
		if jsonOut {
			return
		}
		if verdict == "ERROR" {
			fmt.Printf("  %s — ERROR\n", pkg)
		} else {
			fmt.Printf("  %s — %s\n", pkg, verdict)
		}
	}

	ctx := context.Background()
	results := a.AuditUpdateList(ctx, updates, progress)

	if len(results) == 0 {
		fmt.Println("No AUR packages with pending updates found.")
		return
	}

	if jsonOut {
		printResultsJSON(results)
		return
	}

	fmt.Printf("\nAudited %d package(s) with pending updates:\n\n", len(results))

	// Summary table
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PKG\tVERDICT\tCONFIDENCE\tSUMMARY")
	fmt.Fprintln(w, "---\t---\t---\t---")
	for _, r := range results {
		if r.Error != "" {
			fmt.Fprintf(w, "%s\tERROR\t-\t%s\n", r.Package, r.Error)
			continue
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Package, r.Verdict.Verdict, r.Verdict.Confidence, truncate(r.Verdict.Summary, 80))
	}
	w.Flush()

	// Detailed findings
	fmt.Println()
	for _, r := range results {
		if r.Error != "" {
			fmt.Printf("\n── %s (ERROR) ──\n  %s\n", r.Package, r.Error)
			continue
		}
		fmt.Printf("\n── %s (%s, %s confidence) ──\n", r.Package, r.Verdict.Verdict, r.Verdict.Confidence)
		fmt.Println(r.Verdict.Summary)
		if len(r.Verdict.Findings) == 0 {
			fmt.Println("\n  No findings.")
			continue
		}
		fmt.Println()
		for _, f := range r.Verdict.Findings {
			severity := severityLabel(f.Severity)
			fmt.Printf("  %s [%s] line %d: %s\n", severity, f.TTP, f.Line, f.Detail)
		}
	}
}

func printResult(r *audit.PackageResult) {
	icon := verdictLabel(r.Verdict.Verdict)
	fmt.Printf("\n%s  %s — %s (confidence: %s)\n", icon, r.Package, r.Verdict.Verdict, r.Verdict.Confidence)
	fmt.Println(strings.Repeat("─", 60))
	fmt.Println(r.Verdict.Summary)
	fmt.Println()

	if len(r.Verdict.Findings) == 0 {
		fmt.Println("No findings.")
		return
	}

	for _, f := range r.Verdict.Findings {
		if f.Detail == "" && f.TTP == "" {
			continue
		}
		severity := severityLabel(f.Severity)
		fmt.Printf("  %s [%s] line %d: %s\n", severity, f.TTP, f.Line, f.Detail)
	}
	fmt.Println()
}

func severityLabel(s string) string {
	switch s {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return s
	}
}

func verdictLabel(v string) string {
	switch v {
	case "SAFE":
		return "[SAFE]"
	case "SUSPICIOUS":
		return "[SUSPICIOUS]"
	case "MALICIOUS":
		return "[MALICIOUS]"
	default:
		return "[?]"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func printResultJSON(r *audit.PackageResult) {
	json.NewEncoder(os.Stdout).Encode(r)
}

func printResultsJSON(results []*audit.PackageResult) {
	json.NewEncoder(os.Stdout).Encode(results)
}

func loadConfig() audit.Config {
	return audit.LoadConfig(
		"./configs/aurdit.yaml",
		os.ExpandEnv("$HOME/.config/aurdit/config.yaml"),
	)
}

func usage() {
	fmt.Println(`aurdit — audit AUR PKGBUILDs for malicious changes

Usage:
  aurdit <pkgname> [--history 5] [--commit <hash>] [--skills-dir ./skills] [--verbose]
      Audit a package by comparing recent PKGBUILD versions to detect
      anomalous changes. Defaults to the last 5 versions.
      With --commit, center the comparison around a specific commit hash.

  aurdit check [--skills-dir ./skills] [--verbose]
      Discover all installed AUR packages with pending updates and audit
      each one, printing a summary.

Environment:
  DEEPSEEK_API_KEY    DeepSeek API key (required)`)
}
