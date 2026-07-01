package redactor

import (
	"encoding/json"
	"regexp"
	"sync"
)

type RedactionRule struct {
	Name     string
	Regex    *regexp.Regexp
	MaskWith string
}

// RuleSpec is the plain (non-compiled) form used when loading rules
// from config.Config.Redaction.Rules — avoids redactor importing config
// directly and creating an import cycle.
type RuleSpec struct {
	Name     string
	Pattern  string
	MaskWith string
}

var (
	rules []RedactionRule
	once  sync.Once
	mu    sync.RWMutex
)

// Init sets up redaction rules. Pass specs loaded from agentguard.yaml;
// if specs is empty, falls back to the built-in default rule set so the
// proxy still redacts common secrets out of the box.
func Init(specs ...RuleSpec) {
	once.Do(func() {
		if len(specs) == 0 {
			rules = defaultRules()
			return
		}

		compiled := make([]RedactionRule, 0, len(specs))
		for _, s := range specs {
			re, err := regexp.Compile(s.Pattern)
			if err != nil {
				// Skip invalid patterns rather than crashing the proxy
				continue
			}
			compiled = append(compiled, RedactionRule{
				Name:     s.Name,
				Regex:    re,
				MaskWith: s.MaskWith,
			})
		}

		if len(compiled) == 0 {
			compiled = defaultRules()
		}
		rules = compiled
	})
}

func defaultRules() []RedactionRule {
	return []RedactionRule{
		{
			Name:     "OpenAI Key",
			Regex:    regexp.MustCompile(`(?i)sk-[a-zA-Z0-9]{48}`),
			MaskWith: "<REDACTED_API_KEY>",
		},
		{
			Name:     "PostgreSQL Credentials",
			Regex:    regexp.MustCompile(`(?i)postgres://[a-zA-Z0-9_]+:[^@]+@[a-zA-Z0-9.-]+:[0-9]+/?[a-zA-Z0-9_]*`),
			MaskWith: "<REDACTED_DB_URI>",
		},
		{
			Name:     "Generic Secret/Bearer",
			Regex:    regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*`),
			MaskWith: "Bearer <REDACTED_TOKEN>",
		},
		{
			Name:     "Email Address",
			Regex:    regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`),
			MaskWith: "<REDACTED_EMAIL>",
		},
	}
}

// Process cleanses raw parameter JSON payload maps recursively
func Process(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}

	mu.RLock()
	defer mu.RUnlock()

	strInput := string(raw)
	for _, rule := range rules {
		strInput = rule.Regex.ReplaceAllString(strInput, rule.MaskWith)
	}

	return json.RawMessage(strInput)
}