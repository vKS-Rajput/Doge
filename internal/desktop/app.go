package desktop

import (
	"context"
	"sync"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
	"github.com/vKS-Rajput/doge/internal/runtime"
)

// App is the main Wails desktop application struct.
// Its exported methods are automatically bound to the frontend JavaScript runtime (window.go.desktop.App).
type App struct {
	mu          sync.RWMutex
	ctx         context.Context
	dogeRuntime *runtime.Runtime
	eventsBridge *EventsBridge
}

// NewApp creates a new desktop Application instance bound to the DOGE runtime.
func NewApp(rt *runtime.Runtime) *App {
	return &App{
		dogeRuntime: rt,
	}
}

// Startup is called when Wails initializes the native application window.
func (a *App) Startup(ctx context.Context) {
	a.mu.Lock()
	a.ctx = ctx
	a.mu.Unlock()

	// Connect event bridge from DOGE runtime broadcaster to Wails desktop events
	if a.dogeRuntime != nil {
		a.eventsBridge = NewEventsBridge(ctx, a.dogeRuntime.Broadcaster())
		a.eventsBridge.Start()
	}

	wailsRuntime.LogInfof(ctx, "DOGE Desktop Cockpit started successfully")
}

// Shutdown is called when the desktop application terminates.
func (a *App) Shutdown(ctx context.Context) {
	if a.eventsBridge != nil {
		a.eventsBridge.Stop()
	}
	if a.dogeRuntime != nil {
		_ = a.dogeRuntime.Stop()
	}
}

// DomReady is called after the frontend HTML/JS has completed loading.
func (a *App) DomReady(ctx context.Context) {
	wailsRuntime.LogInfof(ctx, "DOGE Desktop DOM is ready")
}

// Context returns the Wails application context.
func (a *App) Context() context.Context {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.ctx
}

// ShowNotification triggers a native OS notification.
func (a *App) ShowNotification(title, message string) {
	a.mu.RLock()
	ctx := a.ctx
	a.mu.RUnlock()
	if ctx != nil {
		wailsRuntime.EventsEmit(ctx, "doge:notification", map[string]string{
			"title":   title,
			"message": message,
		})
	}
}
