#!/usr/bin/env python3
"""Render demo.gif: runs php2shell_check.py against real PHP Docker images and
animates the captured output as a terminal session."""
import os
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FONT_DIR = "/usr/share/fonts/truetype/jetbrains-mono-zorin-os"
FONT = ImageFont.truetype(os.path.join(FONT_DIR, "JetBrainsMono-Regular.ttf"), 15)
BOLD = ImageFont.truetype(os.path.join(FONT_DIR, "JetBrainsMono-Bold.ttf"), 15)
BG, FG, DIM = (13, 17, 23), (201, 209, 217), (125, 133, 144)
GREEN, RED, YELLOW, BLUE = (63, 185, 80), (248, 81, 73), (210, 153, 34), (88, 166, 255)
W, LINE_H, PAD, TOP, ROWS = 1060, 22, 18, 40, 24

SCENES = [
    ("php:8.4.26-cli", ""),
    ("php:8.4.26-cli", "-d memory_limit=-1 -d session.upload_progress.enabled=0"),
    ("php:8.1-cli", ""),
    ("php:8.4-cli", ""),
]


def run(image, php_args):
    env = dict(os.environ, IMAGE=image, PHP_ARGS=php_args)
    res = subprocess.run([sys.executable, "php2shell_check.py", "--php", "demo/dphp.sh"],
                         cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
    return [l for l in res.stdout.splitlines() if not l.startswith("Note:")], res.returncode


def color(line):
    if "PATCHED" in line or "[x]" in line or "exit 0" in line:
        return GREEN
    if "VULNERABLE" in line or "[ ]" in line:
        return RED
    if "BACKPORT" in line or "exit 1" in line:
        return YELLOW
    if line.startswith("#"):
        return DIM
    return FG


def frame(lines, cursor=False):
    img = Image.new("RGB", (W, TOP + ROWS * LINE_H + PAD), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 28], fill=(22, 27, 34))
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([12 + i * 20, 9, 24 + i * 20, 21], fill=c)
    d.text((W // 2 - 70, 6), "php2shell-check", font=FONT, fill=DIM)
    visible = lines[-ROWS:]
    for i, line in enumerate(visible):
        y = TOP + i * LINE_H
        if line.startswith("$ "):
            d.text((PAD, y), "$", font=BOLD, fill=BLUE)
            d.text((PAD + 18, y), line[2:], font=FONT, fill=FG)
        else:
            d.text((PAD, y), line, font=BOLD if line.startswith("PHP ") else FONT, fill=color(line))
    if cursor and visible:
        x = PAD + int(FONT.getlength(visible[-1]))
        y = TOP + (len(visible) - 1) * LINE_H
        d.rectangle([x + 2, y + 2, x + 10, y + 18], fill=FG)
    return img


def main():
    frames, durations = [], []

    def add(lines, ms, cursor=False):
        frames.append(frame(lines, cursor))
        durations.append(ms)

    screen = ["# PHP2Shell (CVE-2026-109618 / CVE-2026-109619) exposure check"]
    add(screen, 1200)
    for image, php_args in SCENES:
        out, code = run(image, php_args)
        note = f"# {image}" + (" with interim mitigations" if php_args else "")
        prefix = f"IMAGE={image} " + (f'PHP_ARGS="{php_args[:28]}..." ' if php_args else "")
        cmd = f"{prefix}./php2shell_check.py --php demo/dphp.sh"
        screen = screen + ["", note]
        typed = "$ "
        for i in range(0, len(cmd), 4):
            typed = "$ " + cmd[: i + 4]
            add(screen + [typed], 45, cursor=True)
        screen = screen + [typed]
        add(screen, 500)
        for line in out:
            screen = screen + [line]
            add(screen, 250)
        screen = screen + [f"exit {code}"]
        add(screen, 2200)
    path = os.path.join(ROOT, "demo", "demo.gif")
    frames[0].save(path, save_all=True, append_images=frames[1:], duration=durations,
                   loop=0, optimize=True)
    print(path, len(frames), "frames", os.path.getsize(path) // 1024, "KB")


if __name__ == "__main__":
    main()
