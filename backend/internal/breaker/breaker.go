package breaker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Breaker struct {
	client            *http.Client
	upstashURL        string
	upstashToken      string
	mu                sync.RWMutex
	fallbackCache     map[string][]time.Time
	windowSeconds     int
	maxCallsPerWindow int
}

// NewBreaker builds a Breaker using the given window (seconds) and call
// threshold. Pass cfg.Breaker.WindowSeconds / cfg.Breaker.MaxCallsPerWindow
// from your loaded config.Config.
func NewBreaker(windowSeconds, maxCallsPerWindow int) *Breaker {
	if windowSeconds <= 0 {
		windowSeconds = 30
	}
	if maxCallsPerWindow <= 0 {
		maxCallsPerWindow = 10
	}
	return &Breaker{
		client: &http.Client{
			Timeout: 400 * time.Millisecond,
		},
		upstashURL:        os.Getenv("UPSTASH_REDIS_REST_URL"),
		upstashToken:      os.Getenv("UPSTASH_REDIS_REST_TOKEN"),
		fallbackCache:     make(map[string][]time.Time),
		windowSeconds:     windowSeconds,
		maxCallsPerWindow: maxCallsPerWindow,
	}
}

// CheckAndIncrement verifies if an agent has executed too many calls in a rolling window
func (b *Breaker) CheckAndIncrement(ctx context.Context, sessionID, method string) (bool, error) {
	cacheKey := fmt.Sprintf("agentguard:%s:%s", sessionID, method)

	if b.upstashURL == "" || b.upstashToken == "" {
		return b.checkInMemoryFallback(cacheKey), nil
	}

	reqURL := fmt.Sprintf("%s/pipeline", b.upstashURL)

	// Dynamically build the pipeline structure to guarantee bulletproof JSON serialization
	cmd1 := []string{"INCR", cacheKey}
	cmd2 := []string{"EXPIRE", cacheKey, fmt.Sprintf("%d", b.windowSeconds)}
	pipeline := [][]string{cmd1, cmd2}

	payloadBytes, err := json.Marshal(pipeline)
	if err != nil {
		return b.checkInMemoryFallback(cacheKey), nil
	}

	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(string(payloadBytes)))
	if err != nil {
		return b.checkInMemoryFallback(cacheKey), nil
	}
	req.Header.Set("Authorization", "Bearer "+b.upstashToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return b.checkInMemoryFallback(cacheKey), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return b.checkInMemoryFallback(cacheKey), nil
	}

	// Upstash pipeline returns an array of JSON results corresponding to command execution
	type pipelineResult struct {
		Result interface{} `json:"result"`
		Error  string      `json:"error,omitempty"`
	}
	var pipelineResponse []pipelineResult

	if err := json.NewDecoder(resp.Body).Decode(&pipelineResponse); err != nil || len(pipelineResponse) == 0 {
		return b.checkInMemoryFallback(cacheKey), nil
	}

	// Correctly index the FIRST element in the slice to parse the result of INCR
	if len(pipelineResponse) > 0 {
		firstResult := pipelineResponse[0]
		if countVal, ok := firstResult.Result.(float64); ok {
			if int(countVal) > b.maxCallsPerWindow {
				return true, nil
			}
		}
	}

	return false, nil
}

func (b *Breaker) checkInMemoryFallback(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Duration(b.windowSeconds) * time.Second)

	var activeCalls []time.Time
	for _, t := range b.fallbackCache[key] {
		if t.After(cutoff) {
			activeCalls = append(activeCalls, t)
		}
	}

	if len(activeCalls) >= b.maxCallsPerWindow {
		b.fallbackCache[key] = activeCalls
		return true // Circuit breaker tripped
	}

	activeCalls = append(activeCalls, now)
	b.fallbackCache[key] = activeCalls
	return false
}