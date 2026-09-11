package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// IPCServer provides a local HTTP and Server-Sent Events (SSE) API for the desktop GUI.
type IPCServer struct {
	mu          sync.RWMutex
	runtime     *Runtime
	listener    net.Listener
	server      *http.Server
	addr        string
	broadcaster *EventBroadcaster
}

// NewIPCServer creates a local IPC server.
func NewIPCServer(rt *Runtime, b *EventBroadcaster) *IPCServer {
	return &IPCServer{
		runtime:     rt,
		broadcaster: b,
	}
}

// Start binds to the given address (e.g. "127.0.0.1:42424" or "127.0.0.1:0" for auto-port) and serves requests.
func (s *IPCServer) Start(addr string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if addr == "" {
		addr = "127.0.0.1:42424"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		// Fallback to auto port if 42424 is taken
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return "", fmt.Errorf("failed to bind IPC listener: %w", err)
		}
	}

	s.listener = ln
	s.addr = ln.Addr().String()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/environment", s.handleEnvironment)
	mux.HandleFunc("/api/workspace", s.handleWorkspace)
	mux.HandleFunc("/api/research/start", s.handleResearchStart)
	mux.HandleFunc("/api/research/pause", s.handleResearchPause)
	mux.HandleFunc("/api/research/resume", s.handleResearchResume)
	mux.HandleFunc("/api/research/stop", s.handleResearchStop)
	mux.HandleFunc("/api/terminal/execute", s.handleTerminalExecute)
	mux.HandleFunc("/api/events", s.handleEventsSSE)
	mux.HandleFunc("/api/worldmodel", s.handleWorldModel)
	mux.HandleFunc("/api/findings", s.handleFindings)

	s.server = &http.Server{
		Handler:      corsMiddleware(mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // 0 allows long-lived SSE streaming
	}

	go func() {
		_ = s.server.Serve(ln)
	}()

	return s.addr, nil
}

// Stop shuts down the IPC server gracefully.
func (s *IPCServer) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

// Addr returns the bound listener address.
func (s *IPCServer) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.addr
}

func (s *IPCServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	state := s.runtime.GetState()
	resources := s.runtime.Governor().Snapshot()
	ws := s.runtime.GetWorkspace()

	resp := map[string]any{
		"state":     string(state),
		"resources": resources,
	}
	if ws != nil {
		resp["workspace"] = ws.Config
		resp["policy"] = ws.Policy
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *IPCServer) handleEnvironment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	env := s.runtime.GetEnvironment()
	writeJSON(w, http.StatusOK, env)
}

func (s *IPCServer) handleWorkspace(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ws := s.runtime.GetWorkspace()
	if ws == nil {
		http.Error(w, "no active workspace", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, ws)
}

func (s *IPCServer) handleResearchStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := s.runtime.StartResearch()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "researching"})
}

func (s *IPCServer) handleResearchPause(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := s.runtime.Pause()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "paused"})
}

func (s *IPCServer) handleResearchResume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := s.runtime.Resume()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "resumed"})
}

func (s *IPCServer) handleResearchStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := s.runtime.Stop()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopped"})
}

func (s *IPCServer) handleTerminalExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ExecutionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	res, err := s.runtime.Execute(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error(), "result": res})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *IPCServer) handleEventsSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := s.broadcaster.Subscribe(128)
	defer s.broadcaster.Unsubscribe(ch)

	// Send initial connected event
	initialBytes, _ := json.Marshal(map[string]string{"status": "connected", "time": time.Now().Format(time.RFC3339)})
	_, _ = fmt.Fprintf(w, "event: connected\ndata: %s\n\n", string(initialBytes))
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-ch:
			if !ok {
				return
			}
			evtBytes, err := json.Marshal(evt)
			if err == nil {
				_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", string(evt.Type), string(evtBytes))
				flusher.Flush()
			}
		}
	}
}

func (s *IPCServer) handleWorldModel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	nodes, edges := s.runtime.GetWorldModelSnapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes": nodes,
		"edges": edges,
	})
}

func (s *IPCServer) handleFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	findings, bundles := s.runtime.GetFindings()
	writeJSON(w, http.StatusOK, map[string]any{
		"findings":      findings,
		"proof_bundles": bundles,
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
