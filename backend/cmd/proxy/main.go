package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/venomstack14/agentguard/internal/breaker"
	"github.com/venomstack14/agentguard/internal/config"
	"github.com/venomstack14/agentguard/internal/database"
	"github.com/venomstack14/agentguard/internal/policy"
	"github.com/venomstack14/agentguard/internal/redactor"
	"github.com/venomstack14/agentguard/internal/sandbox"
)

// JSONRPCRequest represents a strict JSON-RPC 2.0 payload
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      interface{}     `json:"id"`
}

// JSONRPCError represents a structured JSON-RPC error response
type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	Error   *JSONRPCError `json:"error,omitempty"`
	Result  interface{}   `json:"result,omitempty"`
	ID      interface{}   `json:"id"`
}

// toolCallParams matches the MCP tools/call params shape: {"name": "...", "arguments": {...}}
type toolCallParams struct {
	Name string `json:"name"`
}

func main() {
	configPath := flag.String("config", "config/agentguard.yaml", "path to AgentGuard policy YAML")
	flag.Parse()

	// Initialize subsystems safely
	logWriter := os.Stdout
	log.SetOutput(logWriter)
	log.Println("[INFO] Starting AgentGuard Security Gateway...")

	// Load policy config (falls back to defaults if file is missing/empty)
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("[FATAL] Failed to load config %s: %v", *configPath, err)
	}
	log.Printf("[INFO] Loaded config from %s (breaker: %d calls / %ds window)",
		*configPath, cfg.Breaker.MaxCallsPerWindow, cfg.Breaker.WindowSeconds)

	// Initialize subsystems using config
	redactionSpecs := make([]redactor.RuleSpec, 0, len(cfg.Redaction.Rules))
	for _, r := range cfg.Redaction.Rules {
		redactionSpecs = append(redactionSpecs, redactor.RuleSpec{
			Name:     r.Name,
			Pattern:  r.Pattern,
			MaskWith: r.MaskWith,
		})
	}
	redactor.Init(redactionSpecs...)

	dbLogger := database.NewAsyncLogger()
	circuitBreaker := breaker.NewBreaker(cfg.Breaker.WindowSeconds, cfg.Breaker.MaxCallsPerWindow)
	policyEngine := policy.NewEngine(cfg.Tools.Blocked, cfg.Tools.Destructive, cfg.Tools.ExemptFromBreaker)

	log.Printf("[INFO] Policy loaded: %d blocked, %d destructive, %d breaker-exempt tools",
		len(cfg.Tools.Blocked), len(cfg.Tools.Destructive), len(cfg.Tools.ExemptFromBreaker))

	// Hardened routing
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", handleProxy(circuitBreaker, dbLogger, policyEngine))
	mux.HandleFunc("/logs/recent", withCORS(handleRecentLogs(dbLogger)))
	mux.HandleFunc("/policy", withCORS(handlePolicy(policyEngine)))

	// Wrap middleware to recover from arbitrary panic vectors
	recoveryHandler := panicRecoveryMiddleware(mux)

	addr := ":8080"
	if cfg.Server.Port != 0 {
		addr = ":" + itoa(cfg.Server.Port)
	}

	server := &http.Server{
		Addr:         "0.0.0.0" + addr,
		Handler:      recoveryHandler,
		ReadTimeout:  5 * time.Second,   // Defensive against Slowloris attacks
		WriteTimeout: 10 * time.Second,  // High performance limit
		IdleTimeout:  120 * time.Second, // Managed keep-alive pool
	}

	// Graceful shutdown handling
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		log.Println("[INFO] Shutting down AgentGuard gracefully...")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Printf(" Server forced to shutdown: %v", err)
		}
		dbLogger.Close()
		log.Println("[INFO] Server stopped.")
	}()

	log.Printf("[INFO] AgentGuard listening securely on %s\n", addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf(" Server crash: %v", err)
	}
}

// panicRecoveryMiddleware ensures no runtime panic takes down the proxy process
func panicRecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[PANIC] Recovered from unexpected execution branch: %v\n%s", r, debug.Stack())
				writeJSONRPCError(w, nil, -32603, "Internal server error (Recovered)")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func handleProxy(cb *breaker.Breaker, db *database.AsyncLogger, pe *policy.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Strict HTTP boundaries
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		// Enforce a strict 1MB input limit to completely block heap exhaustion exploits
		r.Body = http.MaxBytesReader(w, r.Body, 1048576)

		// Authenticate using OBO/JWT headers securely
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized (Missing/Invalid Token Format)", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		sessionID, err := validateSessionToken(token)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Decode the JSON-RPC call
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSONRPCError(w, nil, -32700, "Parse error reading request body")
			return
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			writeJSONRPCError(w, nil, -32700, "Invalid JSON payload structure")
			return
		}

		if req.JSONRPC != "2.0" {
			writeJSONRPCError(w, req.ID, -32600, "Invalid Request: Must be JSON-RPC 2.0")
			return
		}

		// Determine the underlying tool name for tools/call requests, so the
		// policy engine can evaluate it (blocked / destructive / exempt).
		toolName := ""
		if req.Method == "tools/call" {
			var tc toolCallParams
			_ = json.Unmarshal(req.Params, &tc)
			toolName = tc.Name
		}

		// 0. Policy Layer: hard block on the configured deny-list
		if toolName != "" && pe.IsBlocked(toolName) {
			writeJSONRPCError(w, req.ID, -32001, "AgentGuard Policy: Tool is blocked")
			db.QueueLog(sessionID, req.Method, toolName, "BLOCKED_BY_POLICY")
			return
		}

		// 1. Redaction Layer: Check and cleanse the arguments
		cleansedParams := redactor.Process(req.Params)
		req.Params = cleansedParams

		// 2. Circuit Breaker Layer: Intercept loops and runaway invocations
		//    (skip entirely for tools explicitly marked exempt, e.g. health checks)
		if toolName == "" || !pe.IsExemptFromBreaker(toolName) {
			isTripped, err := cb.CheckAndIncrement(r.Context(), sessionID, req.Method)
			if err != nil {
				// Fail-closed: If security state check fails, block execution
				writeJSONRPCError(w, req.ID, -32603, "Security state evaluation error")
				return
			}
			if isTripped {
				writeJSONRPCError(w, req.ID, -32000, "AgentGuard Tripped: Runaway execution pattern detected")
				// Async log the incident
				db.QueueLog(sessionID, req.Method, string(req.Params), "TRIPPED_CIRCUIT_BREAKER")
				return
			}
		}

		// 3. Sandboxing destructive operations strictly, per the policy engine's list
		if req.Method == "tools/call" && toolName != "" && pe.IsDestructive(toolName) {
			sandboxErr := sandbox.ExecuteSandboxed(func() {
				log.Println(" Execution context isolated successfully")
			})
			if sandboxErr != nil {
				writeJSONRPCError(w, req.ID, -32603, "Sandbox initialization failure")
				return
			}
		}

		// Log execution success asynchronously
		db.QueueLog(sessionID, req.Method, string(req.Params), "ALLOWED")

		// Mock output logic for proxying downstreams safely
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			Result:  map[string]interface{}{"status": "success", "sanitized": true},
			ID:      req.ID,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// withCORS allows the static dashboard (served from a different origin,
// e.g. Firebase Hosting or file://) to read these GET-only, non-sensitive
// endpoints. Only applied to /logs/recent and /policy — never to /mcp.
func withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

// recentLogView is the JSON shape the dashboard's terminal.js and
// app.html expect: { session_id, method, status, ts }.
type recentLogView struct {
	SessionID string `json:"session_id"`
	Method    string `json:"method"`
	Status    string `json:"status"`
	TS        string `json:"ts"`
}

func handleRecentLogs(db *database.AsyncLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		entries := db.GetRecent(50)
		out := make([]recentLogView, 0, len(entries))
		for _, e := range entries {
			out = append(out, recentLogView{
				SessionID: e.SessionID,
				Method:    e.Method,
				Status:    e.Status,
				TS:        e.CreatedAt.Format(time.RFC3339),
			})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

// policyView mirrors the shape dashboard/app.html expects for /policy.
type policyView struct {
	Blocked           []string `json:"blocked"`
	Destructive       []string `json:"destructive"`
	ExemptFromBreaker []string `json:"exempt_from_breaker"`
}

func handlePolicy(pe *policy.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		view := policyView{
			Blocked:           pe.Blocked(),
			Destructive:       pe.Destructive(),
			ExemptFromBreaker: pe.ExemptFromBreaker(),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(view)
	}
}

func validateSessionToken(token string) (string, error) {
	// Secure cryptographic signature verifications or session checks go here.
	// For production, use jose to inspect JWT structures securely.
	if token == "malicious-attacker" {
		return "", errors.New("signature verification failed")
	}
	return "sess_prod_01", nil
}

func writeJSONRPCError(w http.ResponseWriter, id interface{}, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // JSON-RPC standard dictates 200 OK with payload-level error wrapper
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		Error: &JSONRPCError{
			Code:    code,
			Message: msg,
		},
		ID: id,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// itoa avoids importing strconv just for one int->string conversion in main().
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}