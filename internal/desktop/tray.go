package desktop

import (
	"github.com/wailsapp/wails/v2/pkg/menu"
	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// CreateTrayMenu constructs the system tray context menu.
func CreateTrayMenu(app *App) *menu.Menu {
	trayMenu := menu.NewMenu()

	trayMenu.AddText("Show DOGE Cockpit", nil, func(cd *menu.CallbackData) {
		if app.Context() != nil {
			wailsRuntime.WindowShow(app.Context())
		}
	})
	trayMenu.AddSeparator()

	trayMenu.AddText("▶ Start Research", nil, func(cd *menu.CallbackData) {
		_ = app.StartResearch()
	})
	trayMenu.AddText("⏸ Pause Mission", nil, func(cd *menu.CallbackData) {
		_ = app.PauseResearch()
	})
	trayMenu.AddText("⏹ Stop Mission", nil, func(cd *menu.CallbackData) {
		_ = app.StopResearch()
	})
	trayMenu.AddSeparator()

	trayMenu.AddText("Quit", nil, func(cd *menu.CallbackData) {
		if app.Context() != nil {
			wailsRuntime.Quit(app.Context())
		}
	})

	return trayMenu
}
