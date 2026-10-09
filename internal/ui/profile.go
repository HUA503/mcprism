// Package ui centralizes terminal capability detection and the shared visual
// theme (colors, glyphs, severity/grade rendering) so the table report and the
// interactive TUI stay in sync and both degrade correctly on terminals that
// lack color or UTF-8 support (notably legacy Windows conhost).
package ui

import (
	"os"
	"runtime"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

var (
	colorEnabled = true
	asciiSymbols = false
)

// Init configures rendering from explicit flags and the environment. Call it
// once before any output. noColor forces monochrome output, ascii forces the
// ASCII glyph set; otherwise NO_COLOR, TERM=dumb and the Windows console type
// are detected automatically.
func Init(noColor, ascii bool) {
	detectedNoColor := noColor || os.Getenv("NO_COLOR") != "" || strings.EqualFold(os.Getenv("TERM"), "dumb")
	colorEnabled = !detectedNoColor
	if detectedNoColor {
		lipgloss.SetColorProfile(termenv.Ascii)
	}
	asciiSymbols = ascii || !utf8Terminal()
}

// utf8Terminal reports whether the host can be expected to render Unicode
// glyphs. Legacy Windows conhost uses a legacy code page and shows mojibake,
// so it falls back to ASCII unless Windows Terminal or an xterm-style TERM is
// present.
func utf8Terminal() bool {
	if strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return false
	}
	if runtime.GOOS == "windows" {
		return os.Getenv("WT_SESSION") != "" || strings.Contains(strings.ToLower(os.Getenv("TERM")), "xterm")
	}
	return true
}

func ColorEnabled() bool { return colorEnabled }
func ASCII() bool        { return asciiSymbols }

// glyphs maps a logical symbol to its Unicode and ASCII forms.
var glyphs = map[string]struct{ uni, asc string }{
	"diamond": {"◆", "*"},
	"bullet":  {"●", "*"},
	"circle":  {"○", "o"},
	"dotted":  {"◌", "."},
	"check":   {"✓", "[x]"},
	"pointer": {"▸", ">"},
	"branch":  {"↳", "-"},
	"advice":  {"→", ">"},
	"hbar":    {"─", "-"},
	"hellip":  {"…", "..."},
	"middot":  {"·", "|"},
}

// Sym returns the Unicode form of a glyph, or the ASCII fallback when the
// terminal is not UTF-8 capable.
func Sym(key string) string {
	if g, ok := glyphs[key]; ok {
		if asciiSymbols {
			return g.asc
		}
		return g.uni
	}
	return ""
}

// HBar draws a horizontal rule n cells wide.
func HBar(n int) string {
	return strings.Repeat(Sym("hbar"), n)
}
