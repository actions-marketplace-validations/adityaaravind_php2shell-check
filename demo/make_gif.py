#!/usr/bin/env python3
"""Render demo/demo.gif: runs the real CLI (FORCE_COLOR=1) against Docker targets
and animates its ANSI output as a terminal session. Needs Docker and Pillow.

    docker run -d --name p2s-demo-fpm php:8.3.30-fpm
    python3 demo/make_gif.py
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
COLS, ROWS, LH, PAD, TOP = 112, 40, 18, 16, 38
W, H = int(PAD * 2 + CW * COLS), TOP + ROWS * LH + PAD

BG, FG = (13, 17, 23), (201, 209, 217)
ANSI16 = {
    30: (13, 17, 23), 31: (248, 81, 73), 32: (63, 185, 80), 33: (210, 153, 34),
    34: (88, 166, 255), 35: (188, 140, 255), 36: (57, 197, 207), 37: (201, 209, 217),
    90: (110, 118, 129), 91: (255, 123, 114), 92: (86, 211, 100), 93: (227, 179, 65),
    94: (121, 192, 255), 95: (210, 168, 255), 96: (86, 212, 221), 97: (240, 246, 252),
}
SGR = re.compile(r"\x1b\[([0-9;]*)m")

# The shown string is what the viewer reads; the args are what actually runs.
SCENES = [
    ("npx php2shell-check --docker php:8.4.26-cli --container p2s-demo-fpm",
     ["--docker", "php:8.4.26-cli", "--container", "p2s-demo-fpm"]),
    ("npx php2shell-check --docker php:8.4.26-cli --define memory_limit=-1",
     ["--docker", "php:8.4.26-cli", "--define", "memory_limit=-1"]),
    ("npx php2shell-check 8.3.30 8.5.12 --html report.html",
     ["8.3.30", "8.5.12", "--html", "/tmp/p2s-demo-report.html"]),
]


def run(args):
    env = dict(os.environ, FORCE_COLOR="1", COLUMNS=str(COLS))
    out = subprocess.run(["node", "bin/php2shell-check.js", *args], cwd=ROOT, env=env,
                         capture_output=True, text=True, timeout=600).stdout
    return out.replace("/tmp/p2s-demo-report.html", "./report.html").rstrip("\n").split("\n")


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


def frame(lines, cursor=False):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 26], fill=(22, 27, 34))
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([12 + i * 20, 8, 24 + i * 20, 20], fill=c)
    title = "php2shell-check"
    d.text(((W - FONTS[False].getlength(title)) / 2, 5), title, font=FONTS[False], fill=(110, 118, 129))
    view = lines[-ROWS:]
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
        x = PAD + len(SGR.sub("", view[-1])) * CW
        y = TOP + (len(view) - 1) * LH
        d.rectangle([x + 1, y, x + CW - 1, y + LH - 4], fill=FG)
    return img


PROMPT = "\x1b[94m$\x1b[0m "


def main():
    frames, durations = [], []

    def add(lines, ms, cursor=False):
        frames.append(frame(lines, cursor))
        durations.append(ms)

    screen = []
    for shown, args in SCENES:
        out = run(args)
        for i in range(0, len(shown) + 6, 6):
            typed = (PROMPT + shown[:i]).split("\n")
            add(screen + typed, 40, cursor=True)
        screen = screen + (PROMPT + shown).split("\n")
        for i, f in enumerate("⠋⠙⠹⠸⠼⠴"):
            add(screen + [f"  \x1b[36m{f}\x1b[0m Probing targets…"], 90)
        for i in range(0, len(out), 2):
            add(screen + out[: i + 2], 70)
        screen = screen + out + [""]
        add(screen, 3200)
        screen = []
    path = os.path.join(ROOT, "demo", "demo.gif")
    frames[0].save(path, save_all=True, append_images=frames[1:], duration=durations, loop=0, optimize=True)
    print(path, len(frames), "frames", os.path.getsize(path) // 1024, "KB")


if __name__ == "__main__":
    main()
