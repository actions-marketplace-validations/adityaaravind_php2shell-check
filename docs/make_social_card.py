#!/usr/bin/env python3
"""Regenerate docs/social-card.png, the GitHub social preview image.

GitHub renders the social preview at 2:1. docs/dashboard.png is 1280x1000,
so uploading it directly gets centre-cropped and loses the header. This draws
a purpose-built 1280x640 card in the same palette as the HTML dashboard.

Upload the result at Settings -> General -> Social preview.

    python3 docs/make_social_card.py
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 640
PAD = 72

BG = "#0d1117"
CARD = "#161b22"
BORDER = "#30363d"
TEXT = "#e6edf3"
MUTED = "#8b949e"
RED = "#f85149"
GREEN = "#3fb950"

FONTS = "/usr/share/fonts/truetype/dejavu"


def font(name: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(f"{FONTS}/{name}.ttf", size)


def pill(draw, x, y, text, fnt, colour, *, fill=None):
    """Draw an outlined pill, return its right edge."""
    tw = draw.textlength(text, font=fnt)
    h = fnt.size + 18
    w = tw + 34
    draw.rounded_rectangle([x, y, x + w, y + h], radius=h // 2,
                           outline=colour, width=2, fill=fill)
    draw.text((x + 17, y + h / 2), text, font=fnt, fill=colour, anchor="lm")
    return x + w


def main() -> None:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    f_title = font("DejaVuSans-Bold", 66)
    f_tag = font("DejaVuSans", 29)
    f_pill = font("DejaVuSans-Bold", 19)
    f_chip = font("DejaVuSansMono-Bold", 20)
    f_foot = font("DejaVuSans", 21)

    # Red accent rule down the left edge, echoing the dashboard alert bar.
    d.rectangle([0, 0, 7, H], fill=RED)

    y = PAD + 6
    d.text((PAD, y), "php2shell-check", font=f_title, fill=TEXT)
    y += 92

    d.text((PAD, y), "Find every PHP exposed to PHP2Shell on your machines,",
           font=f_tag, fill=MUTED)
    y += 42
    d.text((PAD, y), "images, containers and fleet — in one command.",
           font=f_tag, fill=MUTED)
    y += 70

    x = pill(d, PAD, y, "CVE-2026-109618", f_pill, RED) + 14
    x = pill(d, x, y, "CVE-2026-109619", f_pill, RED) + 14
    pill(d, x, y, "CVSS v4.0 9.2", f_pill, MUTED)

    # A couple of real output rows, so the card shows what the tool returns.
    rows = [
        (RED, "Vulnerable", "php:8.4.26-cli", "8.4.26", "upgrade to 8.4.27"),
        (GREEN, "Patched", "php:8.2-apache", "8.2.35", "8.2.35 >= 8.2.35"),
    ]
    ry = y + 72
    for colour, status, target, version, detail in rows:
        sw = d.textlength(status, font=f_pill) + 26
        d.rounded_rectangle([PAD, ry, PAD + sw, ry + 34], radius=7, fill=colour)
        d.text((PAD + sw / 2, ry + 18), status, font=f_pill, fill="#0d1117",
               anchor="mm")
        d.text((PAD + 150, ry + 18), target, font=f_chip, fill=TEXT, anchor="lm")
        d.text((PAD + 395, ry + 18), version, font=f_chip, fill=MUTED,
               anchor="lm")
        d.text((PAD + 560, ry + 18), detail, font=f_chip, fill=MUTED,
               anchor="lm")
        ry += 48

    # Capability tiles along the bottom, mirroring the dashboard stat cards.
    chips = ["local", "docker images", "containers", "inventories", "urls"]
    gap = 14
    total = W - 2 * PAD
    widths = [d.textlength(c, font=f_chip) + 36 for c in chips]
    scale = (total - gap * (len(chips) - 1)) / sum(widths)
    widths = [w * scale for w in widths]

    top = H - PAD - 96
    x = PAD
    for chip, w in zip(chips, widths):
        d.rounded_rectangle([x, top, x + w, top + 60], radius=10,
                            fill=CARD, outline=BORDER, width=1)
        d.text((x + w / 2, top + 31), chip, font=f_chip, fill=TEXT, anchor="mm")
        x += w + gap

    foot = "read-only  ·  no exploit code  ·  zero dependencies  ·  MIT"
    d.text((PAD, H - PAD + 2), foot, font=f_foot, fill=MUTED, anchor="ls")
    d.text((W - PAD, H - PAD + 2), "Node 18.3+", font=f_foot, fill=GREEN,
           anchor="rs")

    out = Path(__file__).resolve().parent / "social-card.png"
    img.save(out, optimize=True)
    print(f"wrote {out} ({img.size[0]}x{img.size[1]})")


if __name__ == "__main__":
    main()
