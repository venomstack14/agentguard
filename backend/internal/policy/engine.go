package policy

import "sync"

// Engine evaluates tool-call decisions (blocked / destructive / breaker-exempt)
// based on the `tools:` section of agentguard.yaml.
type Engine struct {
	mu          sync.RWMutex
	blocked     map[string]struct{}
	destructive map[string]struct{}
	exempt      map[string]struct{}
}

// NewEngine builds a policy Engine from the three tool lists in config.Config.Tools.
// Pass cfg.Tools.Blocked, cfg.Tools.Destructive, cfg.Tools.ExemptFromBreaker.
func NewEngine(blocked, destructive, exemptFromBreaker []string) *Engine {
	return &Engine{
		blocked:     toSet(blocked),
		destructive: toSet(destructive),
		exempt:      toSet(exemptFromBreaker),
	}
}

func toSet(items []string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, item := range items {
		set[item] = struct{}{}
	}
	return set
}

// IsBlocked reports whether a tool must always be rejected outright.
func (e *Engine) IsBlocked(toolName string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.blocked[toolName]
	return ok
}

// IsDestructive reports whether a tool must be routed through the sandbox
// before execution, regardless of payload contents.
func (e *Engine) IsDestructive(toolName string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.destructive[toolName]
	return ok
}

// IsExemptFromBreaker reports whether a tool should bypass circuit-breaker
// rate limiting entirely (e.g. health checks, pings).
func (e *Engine) IsExemptFromBreaker(toolName string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.exempt[toolName]
	return ok
}

// Blocked returns the current list of blocked tool names.
func (e *Engine) Blocked() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return fromSet(e.blocked)
}

// Destructive returns the current list of destructive (sandboxed) tool names.
func (e *Engine) Destructive() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return fromSet(e.destructive)
}

// ExemptFromBreaker returns the current list of breaker-exempt tool names.
func (e *Engine) ExemptFromBreaker() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return fromSet(e.exempt)
}

func fromSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}

// Reload swaps in new tool lists at runtime (e.g. after a config hot-reload),
// without requiring callers to construct a new Engine.
func (e *Engine) Reload(blocked, destructive, exemptFromBreaker []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.blocked = toSet(blocked)
	e.destructive = toSet(destructive)
	e.exempt = toSet(exemptFromBreaker)
}