#!/usr/bin/env python3
"""Render the demo GIFs: runs the real CLI (FORCE_COLOR=1) against Docker
targets and animates its ANSI output as a terminal session. Needs Docker and
Pillow.

    docker run -d --name p2s-demo-fpm php:8.3.30-fpm
    python3 demo/make_gif.py

Writes one tight GIF per README step (demo/step-*.gif), each auto-sized to its
own output, plus the combined demo/demo.gif used as the hero image.
"""
import os
import re
import subprocess

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FONT_DIR = os.environ.get("DEMO_FONT_DIR", "/usr/share/fonts/truetype/jetbrains-mono-zorin-os")
SIZE = 14
FONTS = {
    False: ImageFont.truetype(os.path.join(FONT_DIR, "JetBrainsMono-Regular.ttf"), SIZE),
    True: ImageFont.truetype(os.path.join(FONT_DIR, "JetBrainsMono-Bold.ttf"), SIZE),
}
# JetBrains Mono lacks a few symbols the CLI prints; draw those with DejaVu.
FALLBACK_DIR = os.environ.get("DEMO_FALLBACK_DIR", "/usr/share/fonts/truetype/dejavu")
FALLBACK = {
    False: ImageFont.truetype(os.path.join(FALLBACK_DIR, "DejaVuSansMono.ttf"), SIZE),
    True: ImageFont.truetype(os.path.join(FALLBACK_DIR, "DejaVuSansMono-Bold.ttf"), SIZE),
}
FALLBACK_CHARS = set("✔✖▲⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
CW = FONTS[False].getlength("M")
COLS, LH, PAD, TOP = 112, 18, 16, 38
MIN_COLS = 64

BG, FG = (13, 17, 23), (201, 209, 217)
ANSI16 = {
    30: (13, 17, 23), 31: (248, 81, 73), 32: (63, 185, 80), 33: (210, 153, 34),
    34: (88, 166, 255), 35: (188, 140, 255), 36: (57, 197, 207), 37: (201, 209, 217),
    90: (110, 118, 129), 91: (255, 123, 114), 92: (86, 211, 100), 93: (227, 179, 65),
    94: (121, 192, 255), 95: (210, 168, 255), 96: (86, 212, 221), 97: (240, 246, 252),
}
SGR = re.compile(r"\x1b\[([0-9;]*)m")

# (slug, title, shown command, real args). The shown string is what the viewer
# reads; the args are what actually runs.
STEPS = [
    ("step-1-run", "Run it",
     "npx php2shell-check 8.3.30 8.5.12",
     ["8.3.30", "8.5.12"]),
    ("step-2-docker", "Scan an image before you ship it",
     "npx php2shell-check --docker php:8.4.26-cli --docker php:8.2-apache",
     ["--docker", "php:8.4.26-cli", "--docker", "php:8.2-apache"]),
    ("step-3-containers", "Scan what is already running",
     "npx php2shell-check --container p2s-demo-fpm",
     ["--container", "p2s-demo-fpm"]),
    ("step-4-mitigations", "Check a mitigation before rolling it out",
     "npx php2shell-check --docker php:8.4.26-cli --define memory_limit=-1",
     ["--docker", "php:8.4.26-cli", "--define", "memory_limit=-1"]),
    ("step-5-report", "Hand someone a report",
     "npx php2shell-check 8.3.30 8.5.12 --html report.html",
     ["8.3.30", "8.5.12", "--html", "/tmp/p2s-demo-report.html"]),
]

PROMPT = "\x1b[94m$\x1b[0m "
_CACHE = {}


def run(args):
    key = tuple(args)
    if key not in _CACHE:
        env = dict(os.environ, FORCE_COLOR="1", COLUMNS=str(COLS))
        out = subprocess.run(["node", "bin/php2shell-check.js", *args], cwd=ROOT, env=env,
                             capture_output=True, text=True, timeout=600).stdout
        _CACHE[key] = out.replace("/tmp/p2s-demo-report.html", "./report.html").rstrip("\n").split("\n")
    return _CACHE[key]


def plain(line):
    return SGR.sub("", line)


def spans(line):
    """Split one ANSI line into (text, fg, bg, bold, dim) runs."""
    fg, bg, bold, dim = None, None, False, False
    out, pos = [], 0
    for m in SGR.finditer(line):
        if m.start() > pos:
            out.append((line[pos:m.start()], fg, bg, bold, dim))
        for code in [int(c) for c in (m.group(1) or "0").split(";") if c]:
            if code == 0:
                fg, bg, bold, dim = None, None, False, False
            elif code == 1:
                bold = True
            elif code == 2:
                dim = True
            elif code == 22:
                bold = dim = False
            elif code == 39:
                fg = None
            elif code == 49:
                bg = None
            elif code in ANSI16:
                fg = ANSI16[code]
            elif 40 <= code <= 47 or 100 <= code <= 107:
                bg = ANSI16[code - 10]
        pos = m.end()
    out.append((line[pos:], fg, bg, bold, dim))
    return out


def frame(lines, cols, rows, cursor=False):
    w = int(PAD * 2 + CW * cols)
    h = TOP + rows * LH + PAD
    img = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, w, 26], fill=(22, 27, 34))
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([12 + i * 20, 8, 24 + i * 20, 20], fill=c)
    title = "php2shell-check"
    d.text(((w - FONTS[False].getlength(title)) / 2, 5), title, font=FONTS[False], fill=(110, 118, 129))
    view = lines[-rows:]
    for row, line in enumerate(view):
        y = TOP + row * LH
        col = 0
        for text, fg, bg, bold, dim in spans(line):
            if not text:
                continue
            x = PAD + col * CW
            if bg:
                d.rectangle([x, y - 2, x + len(text) * CW, y + LH - 3], fill=bg)
            color = fg or FG
            if dim:
                color = tuple(int(v * 0.6 + b * 0.4) for v, b in zip(color, BG))
            for ch in text:
                x = PAD + col * CW
                if ch == "█":
                    d.rectangle([x, y - 1, x + CW, y + LH - 4], fill=color)
                elif ch != " ":
                    font = FALLBACK[bold] if ch in FALLBACK_CHARS else FONTS[bold]
                    d.text((x, y), ch, font=font, fill=color)
                col += 1
    if cursor and view:
        x = PAD + len(plain(view[-1])) * CW
        y = TOP + (len(view) - 1) * LH
        d.rectangle([x + 1, y, x + CW - 1, y + LH - 4], fill=FG)
    return img


def measure(scenes):
    """Rows and columns the tallest/widest scene needs, so nothing is cropped
    and no scene renders half a screen of empty terminal."""
    rows = cols = 0
    for shown, args in scenes:
        screen = (PROMPT + shown).split("\n") + run(args) + [""]
        rows = max(rows, len(screen))
        cols = max(cols, max(len(plain(line)) for line in screen))
    return rows, max(MIN_COLS, min(COLS, cols))


def render(scenes, path, hold=3200):
    rows, cols = measure(scenes)
    frames, durations = [], []

    def add(lines, ms, cursor=False):
        frames.append(frame(lines, cols, rows, cursor))
        durations.append(ms)

    for shown, args in scenes:
        out = run(args)
        screen = []
        for i in range(0, len(shown) + 6, 6):
            add(screen + (PROMPT + shown[:i]).split("\n"), 40, cursor=True)
        screen = (PROMPT + shown).split("\n")
        for f in "⠋⠙⠹⠸⠼⠴":
            add(screen + [f"  \x1b[36m{f}\x1b[0m Probing targets…"], 90)
        for i in range(0, len(out), 2):
            add(screen + out[: i + 2], 70)
        add(screen + out + [""], hold)

    frames[0].save(path, save_all=True, append_images=frames[1:],
                   duration=durations, loop=0, optimize=True)
    print(f"{os.path.relpath(path, ROOT):28} {cols:>3}x{rows:<3} "
          f"{len(frames):>3} frames  {os.path.getsize(path) // 1024:>4} KB")


def main():
    for slug, _title, shown, args in STEPS:
        render([(shown, args)], os.path.join(ROOT, "demo", f"{slug}.gif"))
    hero = [(shown, args) for _s, _t, shown, args in STEPS[1:4]]
    render(hero, os.path.join(ROOT, "demo", "demo.gif"))


if __name__ == "__main__":
    main()
