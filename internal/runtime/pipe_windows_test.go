//go:build windows

package runtime

import (
	"bufio"
	"context"
	"encoding/json"
	"testing"
	"time"

	winio "github.com/Microsoft/go-winio"
)

func TestNamedPipeIPC(t *testing.T) {
	pipePath := `\\.\pipe\doge-ipc-test`
	rt := NewRuntime(RuntimeConfig{
		WorkspaceRoot: t.TempDir(),
		TargetURL:     "https://test.example.com",
		RequestBudget: 100,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := rt.Start(ctx); err != nil {
		t.Fatalf("Failed to start runtime: %v", err)
	}
	defer func() { _ = rt.Stop() }()

	server := NewPipeServer(rt, rt.Broadcaster())
	if err := server.Start(pipePath); err != nil {
		t.Fatalf("Failed to start pipe server: %v", err)
	}
	defer func() { _ = server.Stop() }()

	time.Sleep(100 * time.Millisecond)

	// Connect client
	conn, err := winio.DialPipe(pipePath, nil)
	if err != nil {
		t.Fatalf("Failed to dial named pipe: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Send ping
	req := PipeMessage{
		ID:     "msg-1",
		Action: "ping",
	}
	reqData, _ := json.Marshal(req)
	reqData = append(reqData, '\n')
	if _, err := conn.Write(reqData); err != nil {
		t.Fatalf("Failed to write to pipe: %v", err)
	}

	reader := bufio.NewReader(conn)
	respLine, err := reader.ReadBytes('\n')
	if err != nil {
		t.Fatalf("Failed to read response from pipe: %v", err)
	}

	var resp PipeMessage
	if err := json.Unmarshal(respLine, &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if !resp.Success {
		t.Errorf("Expected success response, got: %s", resp.Error)
	}
	if resp.ID != "msg-1" {
		t.Errorf("Expected ID 'msg-1', got '%s'", resp.ID)
	}

	// Send status.get
	req = PipeMessage{
		ID:     "msg-2",
		Action: "status.get",
	}
	reqData, _ = json.Marshal(req)
	reqData = append(reqData, '\n')
	if _, err := conn.Write(reqData); err != nil {
		t.Fatalf("Failed to write status.get to pipe: %v", err)
	}

	respLine, err = reader.ReadBytes('\n')
	if err != nil {
		t.Fatalf("Failed to read status response: %v", err)
	}

	if err := json.Unmarshal(respLine, &resp); err != nil {
		t.Fatalf("Failed to unmarshal status response: %v", err)
	}
	if !resp.Success {
		t.Errorf("Expected success for status.get, got: %s", resp.Error)
	}
}
