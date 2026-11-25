#!/usr/bin/env python3
"""Shared metadata and portable fonts for generated mcprism demo assets."""
from pathlib import Path
import re

from PIL import ImageFont

ROOT = str(Path(__file__).resolve().parent.parent)
CHANGELOG = Path(ROOT) / "CHANGELOG.md"


def release_metadata():
    """Return the latest released version and date from the changelog."""
    text = CHANGELOG.read_text(encoding="utf-8")
    match = re.search(r"^## \[(\d+\.\d+\.\d+)\] - (\d{4}-\d{2}-\d{2})$", text, re.MULTILINE)
    if not match:
        raise RuntimeError(f"No released version found in {CHANGELOG}")
    return f"v{match.group(1)}", match.group(2)


def load_fonts(size):
    """Load regular and bold monospace fonts on Windows, macOS, or Linux."""
    candidates = [
        (r"C:\Windows\Fonts\CascadiaMono.ttf", r"C:\Windows\Fonts\CascadiaMono.ttf"),
        (r"C:\Windows\Fonts\consola.ttf", r"C:\Windows\Fonts\consolab.ttf"),
        ("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
         "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"),
        ("/System/Library/Fonts/Menlo.ttc", "/System/Library/Fonts/Menlo.ttc"),
    ]
    for regular, bold in candidates:
        if Path(regular).is_file() and Path(bold).is_file():
            return ImageFont.truetype(regular, size), ImageFont.truetype(bold, size)
    raise FileNotFoundError("Install Cascadia Mono, Consolas, DejaVu Sans Mono, or Menlo to render demo assets")