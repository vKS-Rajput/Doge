package tui

// input provides a minimal text input component without
// external clipboard dependencies.

// InputField is a simple text input that doesn't require
// the atotto/clipboard package.
type InputField struct {
	value       []rune
	cursor      int
	placeholder string
	focused     bool
	width       int
}

// NewInputField creates a new input field.
func NewInputField() InputField {
	return InputField{
		width: 60,
	}
}

// SetPlaceholder sets the placeholder text.
func (i *InputField) SetPlaceholder(s string) {
	i.placeholder = s
}

// Focus gives the input focus.
func (i *InputField) Focus() {
	i.focused = true
}

// Blur removes focus.
func (i *InputField) Blur() {
	i.focused = false
}

// Value returns the current input value.
func (i InputField) Value() string {
	return string(i.value)
}

// SetValue sets the input value.
func (i *InputField) SetValue(s string) {
	i.value = []rune(s)
	i.cursor = len(i.value)
}

// HandleKey processes a key press. Returns true if consumed.
func (i *InputField) HandleKey(key string) bool {
	if !i.focused {
		return false
	}

	switch key {
	case "backspace":
		if i.cursor > 0 {
			i.value = append(i.value[:i.cursor-1], i.value[i.cursor:]...)
			i.cursor--
		}
		return true
	case "delete":
		if i.cursor < len(i.value) {
			i.value = append(i.value[:i.cursor], i.value[i.cursor+1:]...)
		}
		return true
	case "left":
		if i.cursor > 0 {
			i.cursor--
		}
		return true
	case "right":
		if i.cursor < len(i.value) {
			i.cursor++
		}
		return true
	case "home", "ctrl+a":
		i.cursor = 0
		return true
	case "end", "ctrl+e":
		i.cursor = len(i.value)
		return true
	case "ctrl+u":
		i.value = nil
		i.cursor = 0
		return true
	}

	return false
}

// InsertRune adds a character at the cursor position.
func (i *InputField) InsertRune(r rune) {
	if !i.focused {
		return
	}
	newVal := make([]rune, len(i.value)+1)
	copy(newVal, i.value[:i.cursor])
	newVal[i.cursor] = r
	copy(newVal[i.cursor+1:], i.value[i.cursor:])
	i.value = newVal
	i.cursor++
}

// View renders the input field.
func (i InputField) View() string {
	if len(i.value) == 0 && !i.focused {
		return DimText.Render(i.placeholder)
	}
	if len(i.value) == 0 {
		return DimText.Render(i.placeholder) + "▎"
	}

	text := string(i.value)
	if i.focused {
		text += "▎"
	}
	return text
}
