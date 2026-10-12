#!/usr/bin/env python3
# Render a high-resolution static terminal shot of `mcprism vet` on a Go file.
# The rows mirror the real table output of `mcprism vet internal/sast/testdata/vuln.go`.
from PIL import Image, ImageDraw, ImageFont

MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONOB = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
FS = 18
font = ImageFont.truetype(MONO, FS)
fontb = ImageFont.truetype(MONOB, FS)

BG = (24, 24, 37)
FG = (205, 214, 244)
DIM = (108, 112, 134)
GREEN = (166, 227, 161)
RED = (243, 139, 168)
YELLOW = (249, 226, 175)
ORANGE = (250, 179, 135)
RULE = (69, 71, 90)

CELLW = int(round(font.getlength("M")))
LINEH = 24
PAD = 20
HBAR = 88

def finding(sev, sevcol, rule, title, loc, code, advice):
    return [
        [("  " + sev.ljust(4) + " ", sevcol, True), (rule, DIM, False), ("  " + title, FG, False)],
        [("      \u21b3 " + loc, DIM, False)],
        [("      " + code, sevcol, False)],
        [("      \u2192 " + advice, GREEN, False)],
    ]

rows = [
    [("\u25c6 mcprism", FG, True), ("   v0.7.0", DIM, False), ("  \u00b7 2026-10-12", DIM, False)],
    [("\u2500" * HBAR, RULE, False)],
    [(" F ", RED, True), (" ", FG, False), ("vuln", FG, True),
     ("  ", FG, False), ("\u25cc static only", DIM, False)],
    [("  source file: internal/sast/testdata/vuln.go", DIM, False)],
    [("  vet \u00b7 vet (source file)", DIM, False)],
    [("  capabilities: none", DIM, False)],
    [("", FG, False)],
]
rows += finding("CRIT", RED, "MCP801", "Tool argument passed to an OS shell",
    "vuln.go:20", 'c := exec.Command("sh", "-c", command)',
    "Avoid running a shell over agent input. Call exec.Command with a fixed program and\u2026")
rows += finding("HIGH", ORANGE, "MCP802", "Tool argument controls a request URL (SSRF)",
    "vuln.go:29", "r, err := http.Get(target)",
    "Do not let agent input choose the host. Pin a constant base URL or allow-list hosts, and\u2026")
rows += finding("HIGH", ORANGE, "MCP803", "Tool argument used as a file path",
    "vuln.go:40", "data, err := os.ReadFile(p)",
    "Resolve the path, confirm it stays inside one base directory with HasPrefix, and reject\u2026")
rows += finding("HIGH", ORANGE, "MCP806", "Hardcoded secret in server source",
    "vuln.go:13", 'var apiToken = "***"',
    "Load the secret from an environment variable or secret store and rotate the exposed value.")
rows += [
    [("", FG, False)],
    [("\u2500" * HBAR, RULE, False)],
    [("  1 servers (0 reachable) \u00b7 0 tools \u00b7 ", DIM, False), ("4 findings", YELLOW, True)],
    [("  ", DIM, False), ("1 CRIT", RED, True), ("   ", DIM, False), ("3 HIGH", ORANGE, True),
     ("   ", DIM, False), ("0 MED", DIM, False), ("   ", DIM, False), ("0 LOW", DIM, False)],
]

maxlen = max(sum(len(s[0]) for s in r) for r in rows)
W = PAD * 2 + (maxlen + 2) * CELLW
H = PAD * 2 + len(rows) * LINEH
img = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(img)

for ri, row in enumerate(rows):
    y = PAD + ri * LINEH
    x = PAD
    for text, color, bold in row:
        f = fontb if bold else font
        d.text((x, y), text, font=f, fill=color)
        x += len(text) * CELLW

import os as _os
ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
out = _os.path.join(ROOT, "assets", "sast.png")
img.save(out)
print("saved", out, img.size)
