package rules

import (
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// confusable maps Cyrillic/Greek letters that are visually near-identical to
// Latin ones, the classic homoglyph attack (e.g. Cyrillic а U+0430 for Latin a
// in "ignоre"). After NFKC normalization these are folded to Latin so the
// English injection signatures still match.
var confusable = map[rune]rune{
	// Cyrillic lowercase
	0x0430: 'a', 0x0435: 'e', 0x043E: 'o', 0x0440: 'p', 0x0441: 'c',
	0x0443: 'y', 0x0445: 'x', 0x0455: 's', 0x0456: 'i', 0x0458: 'j',
	0x0433: 'r', 0x043F: 'n', 0x0450: 'q', 0x0452: 'd', 0x0457: 'i',
	0x0463: 'y',
	// Cyrillic uppercase
	0x0410: 'A', 0x0412: 'B', 0x0415: 'E', 0x041A: 'K', 0x041C: 'M',
	0x041D: 'H', 0x041E: 'O', 0x0420: 'P', 0x0421: 'C', 0x0422: 'T',
	0x0425: 'X', 0x0406: 'I', 0x0408: 'J', 0x0405: 'S', 0x0404: 'E',
	// Greek
	0x03BF: 'o', 0x039F: 'O', 0x03BD: 'v', 0x03B1: 'a', 0x03C1: 'p',
	0x03C2: 's', 0x03B5: 'e', 0x03C4: 't', 0x03B9: 'i', 0x03BA: 'k',
	0x03BC: 'm', 0x03C5: 'u', 0x03C7: 'x', 0x03B7: 'n', 0x03B6: 'z',
	0x0391: 'A', 0x0392: 'B', 0x0395: 'E', 0x0396: 'Z', 0x0397: 'H',
	0x0399: 'I', 0x039A: 'K', 0x039C: 'M', 0x039D: 'N',
	0x03A1: 'P', 0x03A4: 'T', 0x03A5: 'Y', 0x03A7: 'X',
}

// normalizeForScan folds away text-level obfuscation before matching English
// injection signatures: NFKC (full-width Latin/digits, ligatures, super/
// subscripts, compatibility forms) followed by Cyrillic/Greek-to-Latin
// confusable folding. It does not modify what is shown in the report; it only
// decides whether a signature is present.
func normalizeForScan(s string) string {
	s = norm.NFKC.String(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if mapped, ok := confusable[r]; ok {
			b.WriteRune(mapped)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// findInvisible reports high-risk invisible/format code points. It covers the
// fixed zero-width and bidi controls plus the Unicode Tags block
// (U+E0000–U+E07F), which is used for tag-based invisibility and is not in the
// old hard-coded allowlist. Legitimate formatting such as soft hyphens and
// Arabic/Hebrew letter marks is intentionally left out to avoid false reports
// on non-Latin metadata.
func findInvisible(s string) (r rune, kind string, ok bool) {
	for _, r := range s {
		switch {
		case r == 0x200B || r == 0x200C || r == 0x200D || r == 0xFEFF ||
			r == 0x2060 || r == 0x2061 || r == 0x2062 || r == 0x2063 || r == 0x2064:
			return r, "zero-width/format", true
		case isBidi(r):
			return r, "bidirectional", true
		case r >= 0xE0000 && r <= 0xE007F:
			return r, "Unicode Tags block", true
		}
	}
	return 0, "", false
}

func isBidi(r rune) bool {
	switch r {
	case 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
		0x2066, 0x2067, 0x2068, 0x2069, 0x061C:
		return true
	}
	return false
}

// findMixedScriptToken returns the first whitespace-delimited token that mixes
// Latin letters with Cyrillic or Greek letters, which is overwhelmingly a
// homoglyph attempt (a normal English word has no Cyrillic, and a normal
// Russian word has no Latin). Pure Cyrillic/Greek text is not flagged.
func findMixedScriptToken(s string) string {
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.Is(unicode.Mn, r)
	}) {
		var latin, cyrillic, greek bool
		for _, r := range tok {
			switch {
			case unicode.Is(unicode.Latin, r):
				latin = true
			case unicode.Is(unicode.Cyrillic, r):
				cyrillic = true
			case unicode.Is(unicode.Greek, r):
				greek = true
			}
		}
		if latin && (cyrillic || greek) {
			return tok
		}
	}
	return ""
}
