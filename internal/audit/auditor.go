// Package audit runs LLM-powered audits on AUR PKGBUILDs using the blades agent framework.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Alfredooe/aurdit/configs"
	"github.com/Alfredooe/aurdit/internal/aur"
	"github.com/go-kratos/blades"
	"github.com/go-kratos/blades/contrib/openai"
	"github.com/go-kratos/blades/skills"
	"github.com/go-kratos/blades/tools"
	"github.com/google/jsonschema-go/jsonschema"
	"gopkg.in/yaml.v3"
)

// Config holds aurdit configuration.
type Config struct {
	Instruction string `yaml:"instruction"`
	Model       string `yaml:"model"`
	BaseURL     string `yaml:"base_url"`
}

// Verdict is the structured output from the LLM audit.
type Verdict struct {
	Verdict    string    `json:"verdict" jsonschema:"Overall assessment: SAFE, SUSPICIOUS, or MALICIOUS"`
	Confidence string    `json:"confidence" jsonschema:"How confident the assessment is: LOW, MEDIUM, or HIGH"`
	Summary    string    `json:"summary" jsonschema:"One paragraph summary of the audit findings"`
	Findings   []Finding `json:"findings" jsonschema:"List of specific findings"`
}

// Finding is one specific issue or observation.
type Finding struct {
	Severity string `json:"severity" jsonschema:"Severity level: CRITICAL, HIGH, MEDIUM, LOW, or INFO"`
	TTP      string `json:"ttp" jsonschema:"MITRE ATT&CK technique ID (e.g. T1195.002, T1059.004, T1027). Use the most specific applicable technique."`
	Line     int    `json:"line" jsonschema:"Approximate line number in the PKGBUILD if applicable"`
	Detail   string `json:"detail" jsonschema:"Detailed explanation of the finding"`
}

// PackageResult holds the audit result for a single package.
type PackageResult struct {
	Package          string  `json:"package"`
	InstalledVersion string  `json:"installed_version,omitempty"`
	AURVersion       string  `json:"aur_version,omitempty"`
	Verdict          Verdict `json:"verdict"`
	Error            string  `json:"error,omitempty"`
}

// Auditor runs audits using an LLM agent.
type Auditor struct {
	model     blades.ModelProvider
	skillsDir string
	config    Config
	verbose   io.Writer // if set, streams LLM output here
}

// LoadConfig tries to load config from the given paths, returning defaults on failure.
func LoadConfig(paths ...string) Config {
	for _, p := range paths {
		if p == "" {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var cfg Config
		if yaml.Unmarshal(data, &cfg) != nil {
			continue
		}
		if cfg.Model == "" {
			cfg.Model = "deepseek-chat"
		}
		if cfg.BaseURL == "" {
			cfg.BaseURL = "https://api.deepseek.com/v1"
		}
		if cfg.Instruction != "" {
			return cfg
		}
	}
	return Config{
		Model:   "deepseek-chat",
		BaseURL: "https://api.deepseek.com/v1",
	}
}

// New creates an Auditor with the given DeepSeek API key, skills directory, and config.
func New(apiKey, skillsDir string, cfg Config) *Auditor {
	model := openai.NewModel(cfg.Model, openai.Config{
		BaseURL: cfg.BaseURL,
		APIKey:  apiKey,
	})
	return &Auditor{model: model, skillsDir: skillsDir, config: cfg}
}

// Verbose enables streaming output to w during audits.
func (a *Auditor) Verbose(w io.Writer) *Auditor {
	a.verbose = w
	return a
}

func (a *Auditor) AuditHistory(ctx context.Context, pkg string, n int) (*PackageResult, error) {
	repo, _, err := aur.Clone(pkg)
	if err != nil {
		return nil, fmt.Errorf("clone %s: %w", pkg, err)
	}
	versions, err := aur.Versions(repo, n)
	if err != nil {
		return nil, fmt.Errorf("get versions for %s: %w", pkg, err)
	}
	if len(versions) == 0 {
		return nil, fmt.Errorf("no PKGBUILD history for %s", pkg)
	}

	return a.auditVersion(ctx, pkg, versions)
}

// AuditCommit audits a specific commit in the package's history.
func (a *Auditor) AuditCommit(ctx context.Context, pkg, commit string, n int) (*PackageResult, error) {
	repo, dir, err := aur.Clone(pkg)
	if err != nil {
		return nil, fmt.Errorf("clone %s: %w", pkg, err)
	}
	versions, err := aur.VersionsAround(repo, dir, commit, n)
	if err != nil {
		return nil, fmt.Errorf("get versions for %s at %s: %w", pkg, commit, err)
	}
	if len(versions) == 0 {
		return nil, fmt.Errorf("commit %s not found in %s", commit, pkg)
	}

	return a.auditVersion(ctx, pkg, versions)
}

// AuditUpdates discovers AUR packages with updates and audits each one.
func (a *Auditor) AuditUpdates(ctx context.Context) ([]*PackageResult, error) {
	updates, err := aur.Updates()
	if err != nil {
		return nil, fmt.Errorf("check updates: %w", err)
	}
	if len(updates) == 0 {
		return nil, nil
	}
	return a.AuditUpdateList(ctx, updates, nil), nil
}

// ListUpdates returns packages with pending AUR updates.
func ListUpdates() ([]aur.Update, error) {
	return aur.Updates()
}

// AuditUpdateList audits a list of updates with progress feedback.
func (a *Auditor) AuditUpdateList(ctx context.Context, updates []aur.Update, progress func(string, string)) []*PackageResult {
	var results []*PackageResult
	for _, u := range updates {
		r, err := a.AuditHistory(ctx, u.Name, 5)
		if err != nil {
			results = append(results, &PackageResult{
				Package:          u.Name,
				InstalledVersion: u.InstalledVersion,
				AURVersion:       u.AURVersion,
				Error:            err.Error(),
			})
			if progress != nil {
				progress(u.Name, "ERROR")
			}
			continue
		}
		r.Package = u.Name
		r.InstalledVersion = u.InstalledVersion
		r.AURVersion = u.AURVersion
		results = append(results, r)
		if progress != nil {
			progress(u.Name, r.Verdict.Verdict)
		}
	}
	return results
}

func (a *Auditor) auditVersion(ctx context.Context, pkg string, versions []aur.Version) (*PackageResult, error) {
	var capturedVerdict Verdict

	// Define a tool that forces the LLM to output structured JSON matching Verdict
	schema, _ := jsonschema.For[Verdict](nil)
	if p, ok := schema.Properties["verdict"]; ok {
		p.Enum = []any{"SAFE", "SUSPICIOUS", "MALICIOUS"}
	}
	if p, ok := schema.Properties["confidence"]; ok {
		p.Enum = []any{"LOW", "MEDIUM", "HIGH"}
	}
	if p, ok := schema.Properties["findings"]; ok && p.Items != nil {
		if fp, ok := p.Items.Properties["severity"]; ok {
			fp.Enum = []any{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
		}
	}

	submitTool, err := tools.NewFunc("report_audit",
		"Submit your audit findings. Call this exactly once after you complete your analysis.",
		func(ctx context.Context, v Verdict) (string, error) {
			capturedVerdict = v
			return "Audit report recorded.", nil
		},
		tools.WithInputSchema(schema),
	)
	if err != nil {
		return nil, fmt.Errorf("create tool: %w", err)
	}

	// Build agent with skills and tool
	agentOpts := []blades.AgentOption{
		blades.WithModel(a.model),
		blades.WithInstruction(a.instruction()),
		blades.WithTools(submitTool),
	}

	if a.skillsDir != "" {
		skillList, err := skills.NewFromDir(a.skillsDir)
		if err != nil {
			return nil, fmt.Errorf("load skills: %w", err)
		}
		agentOpts = append(agentOpts, blades.WithSkills(skillList...))
	}

	agent, err := blades.NewAgent("aurdit", agentOpts...)
	if err != nil {
		return nil, fmt.Errorf("create agent: %w", err)
	}

	prompt := buildPrompt(pkg, versions)
	runner := blades.NewRunner(agent)

	var output *blades.Message
	if a.verbose != nil {
		// Stream mode: print tokens as they arrive
		fmt.Fprintln(a.verbose, "── LLM output ──")
		for msg, err := range runner.RunStream(ctx, blades.UserMessage(prompt)) {
			if err != nil {
				return nil, fmt.Errorf("LLM stream: %w", err)
			}
			output = msg
			for _, part := range msg.Parts {
				switch p := part.(type) {
				case blades.TextPart:
					fmt.Fprint(a.verbose, p.Text)
				case blades.ToolPart:
					fmt.Fprintf(a.verbose, "\n  [tool: %s]", p.Name)
				}
			}
		}
		fmt.Fprintln(a.verbose)
	} else {
		output, err = runner.Run(ctx, blades.UserMessage(prompt))
		if err != nil {
			return nil, fmt.Errorf("LLM call: %w", err)
		}
	}

	// If tool wasn't called (rare), try parsing from text
	if capturedVerdict.Verdict == "" {
		text := stripCodeFences(output.Text())
		if err := json.Unmarshal([]byte(text), &capturedVerdict); err != nil {
			return nil, fmt.Errorf("parse verdict: %w\nraw: %s", err, text)
		}
	}

	return &PackageResult{Package: pkg, Verdict: capturedVerdict}, nil
}

func buildPrompt(pkg string, versions []aur.Version) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("Here are %d sequential versions of the PKGBUILD for package '%s'.\n", len(versions), pkg))
	b.WriteString("They are in reverse chronological order (newest first).\n")
	b.WriteString("Determine if the latest version (v1) contains suspicious changes compared to the pattern established by the older versions.\n\n")

	for i, v := range versions {
		b.WriteString(fmt.Sprintf("--- Version %d (commit %s, %s, %s) ---\n", i+1, v.Hash[:8], v.Author, v.Date.Format("2006-01-02")))
		b.WriteString(v.PKGBUILD)
		if v.Install != "" {
			b.WriteString("\n\n=== INSTALL FILE ===\n")
			b.WriteString(v.Install)
		}
		b.WriteString("\n\n")
	}
	return b.String()
}

func (a *Auditor) instruction() string {
	if a.config.Instruction != "" {
		return a.config.Instruction
	}
	return defaultInstruction()
}

func defaultInstruction() string {
	return configs.DefaultInstruction
}

func stripCodeFences(text string) string {
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "```") {
		// Remove opening fence (```json or ```)
		if idx := strings.Index(text, "\n"); idx != -1 {
			text = text[idx+1:]
		}
		// Remove closing fence
		if idx := strings.LastIndex(text, "```"); idx != -1 {
			text = text[:idx]
		}
	}
	return strings.TrimSpace(text)
}

// APIKey returns the DeepSeek API key from the environment.
func APIKey() string {
	return os.Getenv("DEEPSEEK_API_KEY")
}
