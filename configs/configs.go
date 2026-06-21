// Package configs embeds build-time configuration for aurdit.
package configs

import (
	_ "embed"

	"gopkg.in/yaml.v3"
)

//go:embed aurdit.yaml
var rawConfig []byte

// DefaultInstruction is the embedded instruction from aurdit.yaml.
var DefaultInstruction string

func init() {
	var cfg struct {
		Instruction string `yaml:"instruction"`
	}
	if err := yaml.Unmarshal(rawConfig, &cfg); err == nil && cfg.Instruction != "" {
		DefaultInstruction = cfg.Instruction
	}
}
