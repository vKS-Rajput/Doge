package desktop

import (
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

// DefaultWindowOptions constructs the native window configuration for DOGE.
func DefaultWindowOptions(app *App) *options.App {
	return &options.App{
		Title:             "DOGE — Security Research Operating Environment",
		Width:             1440,
		Height:            920,
		MinWidth:          1024,
		MinHeight:         700,
		Frameless:         false,
		StartHidden:       false,
		HideWindowOnClose: false,
		BackgroundColour:  &options.RGBA{R: 7, G: 10, B: 17, A: 255},
		OnStartup:         app.Startup,
		OnShutdown:        app.Shutdown,
		OnDomReady:        app.DomReady,
		Bind: []any{
			app,
		},
		Windows: &windows.Options{
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
			BackdropType:         windows.Mica,
			Theme:                windows.Dark,
			CustomTheme: &windows.ThemeSettings{
				DarkModeTitleBar:   1,
				DarkModeTitleText:  0x00F0FF,
				DarkModeBorder:     0x0E1424,
				LightModeTitleBar:  0,
				LightModeTitleText: 0,
				LightModeBorder:    0,
			},
		},
	}
}
