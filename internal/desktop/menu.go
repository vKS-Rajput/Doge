package desktop

import (
	"github.com/wailsapp/wails/v2/pkg/menu"
	"github.com/wailsapp/wails/v2/pkg/menu/keys"
	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// CreateApplicationMenu constructs the native application menu bar.
func CreateApplicationMenu(app *App) *menu.Menu {
	appMenu := menu.NewMenu()

	// File Menu
	fileMenu := appMenu.AddSubmenu("File")
	fileMenu.AddText("New Research Mission...", keys.CmdOrCtrl("n"), func(cd *menu.CallbackData) {
		if app.Context() != nil {
			wailsRuntime.EventsEmit(app.Context(), "menu:new_mission")
		}
	})
	fileMenu.AddSeparator()
	fileMenu.AddText("Exit DOGE", keys.CmdOrCtrl("q"), func(cd *menu.CallbackData) {
		if app.Context() != nil {
			wailsRuntime.Quit(app.Context())
		}
	})

	// Research Menu
	researchMenu := appMenu.AddSubmenu("Research")
	researchMenu.AddText("Start Research Loop", keys.Key("F5"), func(cd *menu.CallbackData) {
		_ = app.StartResearch()
	})
	researchMenu.AddText("Pause Research Loop", keys.Key("F6"), func(cd *menu.CallbackData) {
		_ = app.PauseResearch()
	})
	researchMenu.AddText("Stop Research", keys.Shift("F5"), func(cd *menu.CallbackData) {
		_ = app.StopResearch()
	})

	// View Menu
	viewMenu := appMenu.AddSubmenu("View")
	viewMenu.AddText("Command Palette...", keys.Combo("p", keys.CmdOrCtrlKey, keys.ShiftKey), func(cd *menu.CallbackData) {
		if app.Context() != nil {
			wailsRuntime.EventsEmit(app.Context(), "menu:command_palette")
		}
	})
	viewMenu.AddText("Toggle Operator / Scientist Mode", keys.Key("Tab"), func(cd *menu.CallbackData) {
		if app.Context() != nil {
			wailsRuntime.EventsEmit(app.Context(), "menu:toggle_personality")
		}
	})
	viewMenu.AddSeparator()
	viewMenu.AddText("Toggle Fullscreen", keys.Key("F11"), func(cd *menu.CallbackData) {
		if app.Context() != nil {
			wailsRuntime.WindowToggleMaximise(app.Context())
		}
	})

	// Tools Menu
	toolsMenu := appMenu.AddSubmenu("Tools")
	toolsMenu.AddText("Open WSL Laboratory Terminal", keys.Key("`"), func(cd *menu.CallbackData) {
		if app.Context() != nil {
			wailsRuntime.EventsEmit(app.Context(), "menu:open_terminal")
		}
	})
	toolsMenu.AddText("Inspect World Model Graph", keys.CmdOrCtrl("g"), func(cd *menu.CallbackData) {
		if app.Context() != nil {
			wailsRuntime.EventsEmit(app.Context(), "menu:open_worldmodel")
		}
	})

	// Help Menu
	helpMenu := appMenu.AddSubmenu("Help")
	helpMenu.AddText("About DOGE Operating Environment", nil, func(cd *menu.CallbackData) {
		if app.Context() != nil {
			_, _ = wailsRuntime.MessageDialog(app.Context(), wailsRuntime.MessageDialogOptions{
				Type:          wailsRuntime.InfoDialog,
				Title:         "About DOGE",
				Message:       "DOGE — Security Research Operating Environment v3.0\nAutonomous, Evidence-Driven Security Science\n(c) 2026 DOGE Security Research Labs",
				Buttons:       []string{"OK"},
				DefaultButton: "OK",
			})
		}
	})

	return appMenu
}
