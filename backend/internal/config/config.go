package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type RedactionRuleConfig struct {
	Name     string `yaml:"name"`
	Pattern  string `yaml:"pattern"`
	MaskWith string `yaml:"mask_with"`
}

type Config struct {
	Server struct {
		Port     int    `yaml:"port"`
		LogLevel string `yaml:"log_level"`
	} `yaml:"server"`

	Breaker struct {
		WindowSeconds       int     `yaml:"window_seconds"`
		MaxCallsPerWindow   int     `yaml:"max_calls_per_window"`
		SimilarityThreshold float64 `yaml:"similarity_threshold"`
		CooldownSeconds     int     `yaml:"cooldown_seconds"`
	} `yaml:"breaker"`

	Redaction struct {
		Enabled       bool                  `yaml:"enabled"`
		MaskResponses bool                  `yaml:"mask_responses"`
		Rules         []RedactionRuleConfig `yaml:"rules"`
	} `yaml:"redaction"`

	Sandbox struct {
		Enabled      bool   `yaml:"enabled"`
		ScopeDir     string `yaml:"scope_dir"`
		AllowWrite   bool   `yaml:"allow_write"`
		AllowNetwork bool   `yaml:"allow_network"`
		Landlock     bool   `yaml:"landlock"`
	} `yaml:"sandbox"`

	Tools struct {
		Destructive       []string `yaml:"destructive"`
		Blocked           []string `yaml:"blocked"`
		ExemptFromBreaker []string `yaml:"exempt_from_breaker"`
	} `yaml:"tools"`

	Storage struct {
		Upstash struct {
			URLEnv   string `yaml:"url_env"`
			TokenEnv string `yaml:"token_env"`
		} `yaml:"upstash"`
		Supabase struct {
			URLEnv string `yaml:"url_env"`
			KeyEnv string `yaml:"key_env"`
		} `yaml:"supabase"`
	} `yaml:"storage"`

	Alerts struct {
		OnTrip        bool   `yaml:"on_trip"`
		WebhookURLEnv string `yaml:"webhook_url_env"`
	} `yaml:"alerts"`
}

// Load reads and parses the AgentGuard YAML policy file at the given path.
// Returns sane defaults if the file is missing or empty, so the proxy can
// still boot during local development.
func Load(path string) (*Config, error) {
	cfg := &Config{}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			applyDefaults(cfg)
			return cfg, nil
		}
		return nil, err
	}

	if len(data) == 0 {
		applyDefaults(cfg)
		return cfg, nil
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	applyDefaults(cfg)
	return cfg, nil
}

// applyDefaults fills in zero-value fields so a partial or missing YAML
// file never results in a breaker with a 0-call limit or similar foot-guns.
func applyDefaults(cfg *Config) {
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8080
	}
	if cfg.Server.LogLevel == "" {
		cfg.Server.LogLevel = "info"
	}
	if cfg.Breaker.WindowSeconds == 0 {
		cfg.Breaker.WindowSeconds = 30
	}
	if cfg.Breaker.MaxCallsPerWindow == 0 {
		cfg.Breaker.MaxCallsPerWindow = 10
	}
	if cfg.Sandbox.ScopeDir == "" {
		cfg.Sandbox.ScopeDir = "/tmp/agentguard-sessions"
	}
}