#!/usr/bin/env python3
# Render a high-resolution static terminal shot of `mcprism vet` on a Go file.
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
BLUE = (137, 180, 250)
TEAL = (137, 220, 235)
RULE = (69, 71, 90)

CELLW = int(round(font.getlength("M")))
LINEH = 24
PAD = 20

rows = [
    [("  \u25c6 mcprism   ", BLUE, True), ("v0.6.0", GREEN, True), ("   \u00b7 2026-10-07", DIM, False)],
    [("  " + "\u2500" * 72, RULE, False)],
    [("  ", FG, False), ("@F@", RED, True), (" ", FG, False), ("vuln", FG, True),
     ("   \u00b7 static only", DIM, False)],
    [("    source file: internal/sast/testdata/vuln.go", DIM, False)],
    [("    vet \u00b7 vet (source file)", DIM, False)],
    [("    capabilities: none", DIM, False)],
    [("", FG, False)],
    [("  CRIT ", RED, True), ("MCP801", TEAL, False), ("  Tool argument passed to an OS shell", FG, True)],
    [("      c := ", FG, False), ("exec", BLUE, False), (".", FG, False), ("Command", BLUE, False),
     ("(", FG, False), ('"sh"', GREEN, False), (", ", FG, False), ('"-c"', GREEN, False),
     (", ", FG, False), ("command", RED, True), (")", FG, False)],
    [("  HIGH ", ORANGE, True), ("MCP802", TEAL, False), ("  Tool argument controls a request URL (SSRF)", FG, True)],
    [("      r, err := ", FG, False), ("http", BLUE, False), (".", FG, False), ("Get", BLUE, False),
     ("(", FG, False), ("target", RED, True), (")", FG, False)],
    [("  HIGH ", ORANGE, True), ("MCP803", TEAL, False), ("  Tool argument used as a file path", FG, True)],
    [("      data, err := ", FG, False), ("os", BLUE, False), (".", FG, False), ("ReadFile", BLUE, False),
     ("(", FG, False), ("p", RED, True), (")", FG, False)],
    [("  HIGH ", ORANGE, True), ("MCP806", TEAL, False), ("  Hardcoded secret in server source", FG, True)],
    [("      ", FG, False), ("var", BLUE, False), (" apiToken = ", FG, False),
     ('"sk-1234567890abcdefghijklmnop"', RED, True)],
    [("", FG, False)],
    [("  " + "\u2500" * 72, RULE, False)],
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
        if text == "@F@":
            d.rounded_rectangle([x, y - 2, x + CELLW + 4, y + LINEH - 4], 5, fill=RED)
            d.text((x + 4, y), "F", font=fontb, fill=BG)
            x += CELLW + 8
            continue
        f = fontb if bold else font
        d.text((x, y), text, font=f, fill=color)
        x += len(text) * CELLW

import os as _os
ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
out = _os.path.join(ROOT, "assets", "sast.png")
img.save(out)
print("saved", out, img.size)
