package database

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

type LogEntry struct {
	SessionID string    `json:"session_id"`
	Method    string    `json:"method"`
	Payload   string    `json:"payload"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// recentBufferSize caps how many log entries are kept in memory for fast
// dashboard reads via GetRecent(). This is separate from persistence in
// Supabase, which is unbounded (subject to Supabase's own free-tier limits).
const recentBufferSize = 200

type AsyncLogger struct {
	queue  chan LogEntry
	client *http.Client
	url    string
	apiKey string
	wg     sync.WaitGroup
	quit   chan struct{}

	recentMu sync.RWMutex
	recent   []LogEntry // ring buffer, most recent last
}

func NewAsyncLogger() *AsyncLogger {
	logger := &AsyncLogger{
		queue:  make(chan LogEntry, 5000),
		client: &http.Client{Timeout: 1 * time.Second},
		url:    os.Getenv("SUPABASE_URL"),
		apiKey: os.Getenv("SUPABASE_KEY"),
		quit:   make(chan struct{}),
		recent: make([]LogEntry, 0, recentBufferSize),
	}

	logger.wg.Add(1)
	go logger.worker()

	return logger
}

func (al *AsyncLogger) QueueLog(sessionID, method, payload, status string) {
	entry := LogEntry{
		SessionID: sessionID,
		Method:    method,
		Payload:   payload,
		Status:    status,
		CreatedAt: time.Now(),
	}

	al.pushRecent(entry)

	select {
	case al.queue <- entry:
	default:
		fmt.Fprintln(os.Stderr, " Queue saturated: Dropping security metric logs safely to prevent connection lag")
	}
}

// pushRecent appends to the in-memory ring buffer used by GetRecent().
// This runs synchronously on the calling goroutine (the HTTP handler),
// so it stays a cheap slice append/trim rather than anything blocking.
func (al *AsyncLogger) pushRecent(entry LogEntry) {
	al.recentMu.Lock()
	defer al.recentMu.Unlock()

	al.recent = append(al.recent, entry)
	if len(al.recent) > recentBufferSize {
		al.recent = al.recent[len(al.recent)-recentBufferSize:]
	}
}

// GetRecent returns up to `limit` of the most recently queued log entries,
// newest first. Backed by an in-memory buffer (not a Supabase query), so
// it's safe to call frequently, e.g. from a dashboard polling every few
// seconds, without adding load to Supabase or introducing extra latency.
func (al *AsyncLogger) GetRecent(limit int) []LogEntry {
	al.recentMu.RLock()
	defer al.recentMu.RUnlock()

	n := len(al.recent)
	if limit <= 0 || limit > n {
		limit = n
	}

	out := make([]LogEntry, limit)
	// al.recent is oldest-first; reverse into out so result is newest-first
	for i := 0; i < limit; i++ {
		out[i] = al.recent[n-1-i]
	}
	return out
}

func (al *AsyncLogger) worker() {
	defer al.wg.Done()

	for {
		select {
		case entry := <-al.queue:
			al.sendLogToSupabase(entry)
		case <-al.quit:
			for len(al.queue) > 0 {
				al.sendLogToSupabase(<-al.queue)
			}
			return
		}
	}
}

func (al *AsyncLogger) sendLogToSupabase(entry LogEntry) {
	if al.url == "" || al.apiKey == "" {
		return
	}

	endpoint := fmt.Sprintf("%s/rest/v1/audit_logs", al.url)
	body, err := json.Marshal(entry)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return
	}
	req.Header.Set("apikey", al.apiKey)
	req.Header.Set("Authorization", "Bearer "+al.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Prefer", "return=minimal")

	resp, err := al.client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, " Logging database payload failed: %v\n", err)
		return
	}
	_ = resp.Body.Close()
}

func (al *AsyncLogger) Close() {
	close(al.quit)
	al.wg.Wait()
}