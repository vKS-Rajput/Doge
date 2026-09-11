//go:build !windows

package runtime

import (
	"fmt"
)

const (
	DefaultPipePath = "/tmp/doge-ipc.sock"
	ProtocolVersion = "1.0.0"
)

type PipeMessage struct {
	ID            string `json:"id,omitempty"`
	CorrelationID string `json:"correlation_id,omitempty"`
	Action        string `json:"action,omitempty"`
	Event         string `json:"event,omitempty"`
	Source        string `json:"source,omitempty"`
	Success       bool   `json:"success"`
	Error         string `json:"error,omitempty"`
	Timestamp     string `json:"timestamp"`
	Version       string `json:"version,omitempty"`
}

type PipeServer struct {
	runtime     *Runtime
	broadcaster *EventBroadcaster
}

func NewPipeServer(rt *Runtime, b *EventBroadcaster) *PipeServer {
	return &PipeServer{
		runtime:     rt,
		broadcaster: b,
	}
}

func (s *PipeServer) Start(pipePath string) error {
	return fmt.Errorf("named pipes are only supported on Windows")
}

func (s *PipeServer) Stop() error {
	return nil
}

func (s *PipeServer) Path() string {
	return DefaultPipePath
}
