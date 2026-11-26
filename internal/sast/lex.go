package sast

import "strings"

// maskJSComments removes JavaScript and TypeScript comments while preserving
// offsets and newlines. Quoted strings and template literals are left intact so
// values used in sinks remain available to the pattern checks.
func maskJSComments(src string) string {
	b := []byte(src)
	mask := func(start, end int) {
		for i := start; i < end && i < len(b); i++ {
			if b[i] != '\n' && b[i] != '\r' {
				b[i] = ' '
			}
		}
	}
	for i := 0; i < len(b); {
		if b[i] == '\'' || b[i] == '"' || b[i] == '`' {
			quote := b[i]
			i++
			for i < len(b) {
				if b[i] == '\\' {
					i += 2
					continue
				}
				if b[i] == quote {
					i++
					break
				}
				i++
			}
			continue
		}
		if b[i] == '/' && i+1 < len(b) && b[i+1] == '/' {
			start := i
			i += 2
			for i < len(b) && b[i] != '\n' && b[i] != '\r' {
				i++
			}
			mask(start, i)
			continue
		}
		if b[i] == '/' && i+1 < len(b) && b[i+1] == '*' {
			start := i
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			if i+1 < len(b) {
				i += 2
			}
			mask(start, i)
			continue
		}
		i++
	}
	return string(b)
}

// maskJSCode blanks comments and string literals while preserving offsets.
// It is used to locate executable syntax; callers can slice the original text
// at matching offsets when literal values are relevant.
func maskJSCode(src string) string {
	b := []byte(maskJSComments(src))
	for i := 0; i < len(b); {
		if b[i] != '\'' && b[i] != '"' && b[i] != '`' {
			i++
			continue
		}
		start, quote := i, b[i]
		i++
		for i < len(b) {
			if b[i] == '\\' {
				i += 2
				continue
			}
			if b[i] == quote {
				i++
				break
			}
			i++
		}
		for j := start; j < i && j < len(b); j++ {
			if b[j] != '\n' && b[j] != '\r' {
				b[j] = ' '
			}
		}
	}
	return string(b)
}

// maskPythonComments replaces comments with spaces while preserving source
// offsets and newlines. Quotes are tracked so `#` inside strings is retained.
func maskPythonComments(src string) string {
	b := []byte(src)
	var quote byte
	triple := false
	for i := 0; i < len(b); {
		if quote != 0 {
			if b[i] == '\\' {
				i += 2
				continue
			}
			if triple && i+2 < len(b) && b[i] == quote && b[i+1] == quote && b[i+2] == quote {
				quote, triple = 0, false
				i += 3
				continue
			}
			if !triple && b[i] == quote {
				quote = 0
			}
			i++
			continue
		}
		if b[i] == '#' {
			for i < len(b) && b[i] != '\n' {
				b[i] = ' '
				i++
			}
			continue
		}
		if b[i] == '\'' || b[i] == '"' {
			quote = b[i]
			if i+2 < len(b) && b[i+1] == quote && b[i+2] == quote {
				triple = true
				i += 3
				continue
			}
		}
		i++
	}
	return string(b)
}

// maskGoComments removes Go line and block comments while preserving offsets,
// line numbers and quoted string literals used by the sink recognizers.
func maskGoComments(src string) string {
	b := []byte(src)
	const (
		goCode = iota
		goString
		goRune
		goRaw
		goLineComment
		goBlockComment
	)
	state := goCode
	for i := 0; i < len(b); {
		switch state {
		case goCode:
			switch {
			case b[i] == '/' && i+1 < len(b) && b[i+1] == '/':
				b[i], b[i+1] = ' ', ' '
				state = goLineComment
				i += 2
			case b[i] == '/' && i+1 < len(b) && b[i+1] == '*':
				b[i], b[i+1] = ' ', ' '
				state = goBlockComment
				i += 2
			case b[i] == '"':
				state = goString
				i++
			case b[i] == '\'':
				state = goRune
				i++
			case b[i] == '`':
				state = goRaw
				i++
			default:
				i++
			}
		case goString, goRune:
			if b[i] == '\\' {
				i += 2
			} else if state == goString && b[i] == '"' || state == goRune && b[i] == '\'' {
				state = goCode
				i++
			} else {
				i++
			}
		case goRaw:
			if b[i] == '`' {
				state = goCode
			}
			i++
		case goLineComment:
			if b[i] == '\n' {
				state = goCode
				i++
			} else {
				b[i] = ' '
				i++
			}
		case goBlockComment:
			if b[i] == '*' && i+1 < len(b) && b[i+1] == '/' {
				b[i], b[i+1] = ' ', ' '
				state = goCode
				i += 2
			} else {
				if b[i] != '\n' {
					b[i] = ' '
				}
				i++
			}
		}
	}
	return string(b)
}

func maskedPythonLines(lines []srcLine) []srcLine {
	return maskedLines(lines, maskPythonComments)
}

func maskedGoLines(lines []srcLine) []srcLine {
	return maskedLines(lines, maskGoComments)
}

func maskedLines(lines []srcLine, mask func(string) string) []srcLine {
	if len(lines) == 0 {
		return nil
	}
	text := mask(joinLines(lines))
	parts := strings.Split(text, "\n")
	out := make([]srcLine, len(lines))
	for i, line := range lines {
		if i < len(parts) {
			line.text = parts[i]
		}
		out[i] = line
	}
	return out
}
