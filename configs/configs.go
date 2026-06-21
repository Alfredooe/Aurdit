// Package configs embeds aurdit.yaml as the single source of truth for defaults.
package configs

import (
	_ "embed"

	"gopkg.in/yaml.v3"
)

//go:embed aurdit.yaml
var raw []byte

// DefaultInstruction is the embedded instruction from aurdit.yaml.
var DefaultInstruction string

func init() {
	var cfg struct {
		Instruction string `yaml:"instruction"`
	}
	if yaml.Unmarshal(raw, &cfg) == nil && cfg.Instruction != "" {
		DefaultInstruction = cfg.Instruction
	}
}
