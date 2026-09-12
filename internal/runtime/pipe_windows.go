//go:build windows

package runtime

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	winio "github.com/Microsoft/go-winio"
	"github.com/google/uuid"
)

const (
	DefaultPipePath = `\\.\pipe\doge-ipc`
	ProtocolVersion = "1.0.0"
)

// PipeMessage represents the strongly-typed JSON envelope used over Windows Named Pipes.
type PipeMessage struct {
	ID            string          `json:"id,omitempty"`
	CorrelationID string          `json:"correlation_id,omitempty"`
	Action        string          `json:"action,omitempty"`
	Event         string          `json:"event,omitempty"`
	Source        string          `json:"source,omitempty"`
	Payload       json.RawMessage `json:"payload,omitempty"`
	Data          any             `json:"data,omitempty"`
	Success       bool            `json:"success"`
	Error         string          `json:"error,omitempty"`
	Timestamp     string          `json:"timestamp"`
	Version       string          `json:"version,omitempty"`
}

// PipeServer manages Windows Named Pipe IPC connections with DOGE desktop clients.
type PipeServer struct {
	mu          sync.RWMutex
	runtime     *Runtime
	broadcaster *EventBroadcaster
	listener    net.Listener
	pipePath    string
	clients     map[net.Conn]struct{}
	ctx         context.Context
	cancel      context.CancelFunc
	closed      bool
}

// NewPipeServer creates a new Windows Named Pipe IPC server.
func NewPipeServer(rt *Runtime, b *EventBroadcaster) *PipeServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &PipeServer{
		runtime:     rt,
		broadcaster: b,
		pipePath:    DefaultPipePath,
		clients:     make(map[net.Conn]struct{}),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Start opens the named pipe listener and begins accepting client connections.
func (s *PipeServer) Start(pipePath string) error {
	s.mu.Lock()
	if pipePath != "" {
		s.pipePath = pipePath
	}

	c := &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;WD)", // Allow all users local access
		MessageMode:        false,            // Stream-oriented
		InputBufferSize:    65536,
		OutputBufferSize:   65536,
	}

	l, err := winio.ListenPipe(s.pipePath, c)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to create named pipe %s: %w", s.pipePath, err)
	}

	s.listener = l
	s.mu.Unlock()

	// Start broadcast listener to push events down the pipe
	go s.eventForwarder()

	// Start accepting incoming pipe clients
	go s.acceptLoop()

	return nil
}

// Stop closes the pipe server and disconnects active clients.
func (s *PipeServer) Stop() error {
	s.mu.Lock()
	s.closed = true
	s.cancel()

	if s.listener != nil {
		_ = s.listener.Close()
	}

	for conn := range s.clients {
		_ = conn.Close()
	}
	s.clients = make(map[net.Conn]struct{})
	s.mu.Unlock()

	return nil
}

// Path returns the active named pipe path.
func (s *PipeServer) Path() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pipePath
}

func (s *PipeServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.mu.RLock()
			closed := s.closed
			s.mu.RUnlock()
			if closed {
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		s.mu.Lock()
		s.clients[conn] = struct{}{}
		s.mu.Unlock()

		go s.handleClient(conn)
	}
}

func (s *PipeServer) handleClient(conn net.Conn) {
	defer func() {
		s.mu.Lock()
		delete(s.clients, conn)
		s.mu.Unlock()
		_ = conn.Close()
	}()

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				// connection dropped or closed
			}
			return
		}

		if len(line) == 0 {
			continue
		}

		var req PipeMessage
		if err := json.Unmarshal(line, &req); err != nil {
			resp := PipeMessage{
				Success:   false,
				Error:     "Invalid JSON request: " + err.Error(),
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Version:   ProtocolVersion,
			}
			s.writeResponse(conn, resp)
			continue
		}

		resp := s.dispatch(req)
		s.writeResponse(conn, resp)
	}
}

func (s *PipeServer) writeResponse(conn net.Conn, msg PipeMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	data = append(data, '\n')
	_, _ = conn.Write(data)
}

func (s *PipeServer) dispatch(req PipeMessage) PipeMessage {
	resp := PipeMessage{
		ID:            req.ID,
		CorrelationID: req.CorrelationID,
		Action:        req.Action,
		Success:       true,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Version:       ProtocolVersion,
	}

	switch req.Action {
	case "ping":
		resp.Data = map[string]string{"message": "pong"}

	case "status.get":
		state := s.runtime.GetState()
		resources := s.runtime.Governor().Snapshot()
		ws := s.runtime.GetWorkspace()
		out := map[string]any{
			"state":     string(state),
			"resources": resources,
		}
		if ws != nil {
			out["workspace"] = ws.Config
			out["policy"] = ws.Policy
		}
		resp.Data = out

	case "environment.get":
		resp.Data = s.runtime.GetEnvironment()

	case "workspace.get":
		resp.Data = s.runtime.GetWorkspace()

	case "research.start":
		if err := s.runtime.StartResearch(); err != nil {
			resp.Success = false
			resp.Error = err.Error()
		} else {
			resp.Data = map[string]string{"status": "research_started"}
		}

	case "research.pause":
		if err := s.runtime.Pause(); err != nil {
			resp.Success = false
			resp.Error = err.Error()
		} else {
			resp.Data = map[string]string{"status": "research_paused"}
		}

	case "research.resume":
		if err := s.runtime.Resume(); err != nil {
			resp.Success = false
			resp.Error = err.Error()
		} else {
			resp.Data = map[string]string{"status": "research_resumed"}
		}

	case "research.stop":
		if err := s.runtime.Stop(); err != nil {
			resp.Success = false
			resp.Error = err.Error()
		} else {
			resp.Data = map[string]string{"status": "research_stopped"}
		}

	case "terminal.execute":
		var p struct {
			Command  string `json:"command"`
			RunInWSL bool   `json:"run_in_wsl"`
		}
		if err := json.Unmarshal(req.Payload, &p); err != nil {
			resp.Success = false
			resp.Error = "Invalid payload: " + err.Error()
			return resp
		}
		if p.Command == "" {
			resp.Success = false
			resp.Error = "Command cannot be empty"
			return resp
		}

		execReq := ExecutionRequest{
			Command:  p.Command,
			RunInWSL: p.RunInWSL,
			Timeout:  60 * time.Second,
		}
		res, err := s.runtime.Execute(context.Background(), execReq)
		if err != nil {
			resp.Success = false
			resp.Error = err.Error()
		} else {
			resp.Data = res
		}

	case "worldmodel.get":
		nodes, edges := s.runtime.GetWorldModelSnapshot()
		resp.Data = map[string]any{
			"nodes": nodes,
			"edges": edges,
		}

	case "findings.get":
		findings, bundles := s.runtime.GetFindings()
		resp.Data = map[string]any{
			"findings":      findings,
			"proof_bundles": bundles,
		}

	case "mission.create":
		var m struct {
			Target    string   `json:"target"`
			Objective string   `json:"objective"`
			Budget    int      `json:"budget"`
			Scope     []string `json:"scope"`
			Risk      string   `json:"risk"`
		}
		if err := json.Unmarshal(req.Payload, &m); err != nil {
			resp.Success = false
			resp.Error = "Invalid mission payload: " + err.Error()
			return resp
		}

		s.broadcaster.Broadcast(
			EventRuntimeReady,
			"mission",
			fmt.Sprintf("New Mission Established for %s (Budget: %d)", m.Target, m.Budget),
			map[string]any{
				"target":    m.Target,
				"objective": m.Objective,
				"budget":    m.Budget,
				"risk":      m.Risk,
			},
		)
	case "gates.list":
		gm := s.runtime.GateManager()
		if gm == nil {
			resp.Data = map[string]any{"pending": []any{}, "all": []any{}}
		} else {
			resp.Data = map[string]any{
				"pending": gm.ListPending(),
				"all":     gm.ListAll(),
			}
		}

	case "gates.approve":
		var p struct {
			GateID string `json:"gate_id"`
			Notes  string `json:"notes"`
		}
		if err := json.Unmarshal(req.Payload, &p); err != nil {
			resp.Success = false
			resp.Error = "Invalid approval payload: " + err.Error()
			return resp
		}
		id, err := uuid.Parse(p.GateID)
		if err != nil {
			resp.Success = false
			resp.Error = "Invalid gate UUID: " + err.Error()
			return resp
		}
		if err := s.runtime.ApproveGate(id, "operator", p.Notes); err != nil {
			resp.Success = false
			resp.Error = err.Error()
		} else {
			resp.Data = map[string]any{"status": "approved", "gate_id": p.GateID}
		}

	case "gates.reject":
		var p struct {
			GateID string `json:"gate_id"`
			Notes  string `json:"notes"`
		}
		if err := json.Unmarshal(req.Payload, &p); err != nil {
			resp.Success = false
			resp.Error = "Invalid rejection payload: " + err.Error()
			return resp
		}
		id, err := uuid.Parse(p.GateID)
		if err != nil {
			resp.Success = false
			resp.Error = "Invalid gate UUID: " + err.Error()
			return resp
		}
		if err := s.runtime.RejectGate(id, "operator", p.Notes); err != nil {
			resp.Success = false
			resp.Error = err.Error()
		} else {
			resp.Data = map[string]any{"status": "rejected", "gate_id": p.GateID}
		}

	case "gates.choose":
		var p struct {
			GateID      string `json:"gate_id"`
			OptionIndex int    `json:"option_index"`
		}
		if err := json.Unmarshal(req.Payload, &p); err != nil {
			resp.Success = false
			resp.Error = "Invalid choice payload: " + err.Error()
			return resp
		}
		id, err := uuid.Parse(p.GateID)
		if err != nil {
			resp.Success = false
			resp.Error = "Invalid gate UUID: " + err.Error()
			return resp
		}
		if err := s.runtime.ChooseGateOption(id, p.OptionIndex, "operator"); err != nil {
			resp.Success = false
			resp.Error = err.Error()
		} else {
			resp.Data = map[string]any{"status": "chosen", "gate_id": p.GateID, "option_index": p.OptionIndex}
		}

	case "research.council":
		c := s.runtime.Council()
		if c == nil {
			resp.Data = map[string]any{"specialists": []any{}}
		} else {
			resp.Data = map[string]any{
				"specialists": c.GetSpecialists(),
			}
		}

	case "notebook.get":
		summary, err := s.runtime.GetNotebookSummary()
		if err != nil {
			resp.Success = false
			resp.Error = err.Error()
		} else {
			resp.Data = summary
		}

	case "note.add":
		var p struct {
			Note     string `json:"note"`
			Category string `json:"category"`
			Target   string `json:"target"`
		}
		if err := json.Unmarshal(req.Payload, &p); err != nil {
			resp.Success = false
			resp.Error = "Invalid note payload: " + err.Error()
			return resp
		}
		noteRes, err := s.runtime.AddResearcherNote(p.Note, p.Category, p.Target)
		if err != nil {
			resp.Success = false
			resp.Error = err.Error()
		} else {
			resp.Data = noteRes
		}

	case "target.get":
		targetSummary, err := s.runtime.GetTargetSummary()
		if err != nil {
			resp.Success = false
			resp.Error = err.Error()
		} else {
			resp.Data = targetSummary
		}

	case "research.get":
		researchSummary, err := s.runtime.GetResearchSummary()
		if err != nil {
			resp.Success = false
			resp.Error = err.Error()
		} else {
			resp.Data = researchSummary
		}

	case "evidence.get":
		evidenceSummary, err := s.runtime.GetEvidenceSummary()
		if err != nil {
			resp.Success = false
			resp.Error = err.Error()
		} else {
			resp.Data = evidenceSummary
		}

	default:
		resp.Success = false
		resp.Error = fmt.Sprintf("Unknown action '%s'", req.Action)
	}

	return resp
}

func (s *PipeServer) eventForwarder() {
	ch := s.broadcaster.Subscribe(128)
	defer s.broadcaster.Unsubscribe(ch)

	for {
		select {
		case <-s.ctx.Done():
			return
		case evt, ok := <-ch:
			if !ok {
				return
			}
			msg := PipeMessage{
				Event:     string(evt.Type),
				Source:    evt.Source,
				Data:      evt.Data,
				Error:     evt.Message,
				Success:   true,
				Timestamp: evt.Timestamp.UTC().Format(time.RFC3339),
				Version:   ProtocolVersion,
			}

			data, err := json.Marshal(msg)
			if err != nil {
				continue
			}
			data = append(data, '\n')

			s.mu.RLock()
			for conn := range s.clients {
				_, _ = conn.Write(data)
			}
			s.mu.RUnlock()
		}
	}
}
