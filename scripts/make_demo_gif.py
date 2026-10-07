#!/usr/bin/env python3
# Render a short terminal recording of `mcprism scan` as a high-resolution GIF.
import os
from PIL import Image, ImageDraw, ImageFont

MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONOB = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
FS = 16
font = ImageFont.truetype(MONO, FS)
fontb = ImageFont.truetype(MONOB, FS)

BG = (30, 30, 46)
BAR = (24, 24, 37)
FG = (205, 214, 244)
DIM = (108, 112, 134)
GREEN = (166, 227, 161)
RED = (243, 139, 168)
YELLOW = (249, 226, 175)
ORANGE = (250, 179, 135)
BLUE = (137, 180, 250)
TEAL = (137, 220, 235)
CURSOR = (245, 224, 220)
RULE = (58, 58, 84)

CELLW = int(round(font.getlength("M")))
LINEH = 21
PAD = 18
BARH = 30

CMD = "mcprism scan examples/dynamic.mcp.json"

# output rows (index 0 is the command line). Each row is a list of (text,color,bold).
def fnd(sev, sc, title):
    return [("  ", FG, False), (sev, sc, True), (" ", FG, False), (f"MCP{sc and ''}", sc, False)]

rows = [
    None,  # 0 command line, filled per frame
    [("", FG, False)],
    [("  \u25c6 mcprism ", BLUE, True), ("v0.6.0", GREEN, True), ("  \u00b7 2026-10-07", DIM, False)],
    [("  " + "\u2500" * 62, RULE, False)],
    [("  ", FG, False), ("\u25cf", GREEN, False), (" demo-server   ", FG, True),
     ("\u25cf connected", GREEN, False)],
    [("    ./bin/testserver", DIM, False)],
    [("    explicit \u00b7 examples/dynamic.mcp.json", DIM, False)],
    [("    capabilities: ", DIM, False), ("SHELL", RED, True), (" \u00b7 ", DIM, False),
     ("READ", YELLOW, True), (" \u00b7 ", DIM, False), ("NETWORK", BLUE, True)],
    [("", FG, False)],
    [("  CRIT ", RED, True), ("MCP201", TEAL, False), ("  Prompt injection in tool metadata", FG, False)],
    [("  HIGH ", ORANGE, True), ("MCP202", TEAL, False), ("  Invisible or bidirectional Unicode in tool metadata", FG, False)],
    [("  CRIT ", RED, True), ("MCP201", TEAL, False), ("  Prompt injection in resource metadata", FG, False)],
    [("  CRIT ", RED, True), ("MCP201", TEAL, False), ("  Prompt injection in prompt metadata", FG, False)],
    [("  CRIT ", RED, True), ("MCP301", TEAL, False), ("  Command execution combined with network access", FG, False)],
    [("  HIGH ", ORANGE, True), ("MCP301", TEAL, False), ("  File read combined with network access", FG, False)],
    [("  HIGH ", ORANGE, True), ("MCP302", TEAL, False), ("  Tool executes arbitrary commands", FG, False)],
    [("  MED  ", YELLOW, True), ("MCP304", TEAL, False), ("  Free-form command parameter without validation", FG, False)],
    [("  MED  ", YELLOW, True), ("MCP306", TEAL, False), ("  Free-form path parameter without validation", FG, False)],
    [("", FG, False)],
    [("  1 servers (1 reachable) \u00b7 5 tools \u00b7 ", DIM, False), ("9 findings", YELLOW, True)],
    [("  ", DIM, False), ("4 CRIT", RED, True), ("   ", DIM, False), ("3 HIGH", ORANGE, True),
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
header = [1, 2, 3, 4, 5, 6, 7, 8]
for k in range(0, len(header), 2):
    for ri in header[k:k + 2]:
        revealed.add(ri)
    frames.append(render(len(CMD), set(revealed)))
    durations.append(70)
for ri in range(9, NROWS):
    revealed.add(ri)
    frames.append(render(len(CMD), set(revealed)))
    durations.append(110 if ri <= 17 else 90)

# 3. hold the final frame
frames.append(render(len(CMD), set(revealed)))
durations.append(1800)

import os as _os
ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
out = _os.path.join(ROOT, "assets", "demo.gif")
frames[0].save(out, save_all=True, append_images=frames[1:], duration=durations,
               loop=0, optimize=True, disposal=2)
print("saved", out, "frames", len(frames), "size", frames[0].size)
