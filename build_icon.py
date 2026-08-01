#!/usr/bin/env python
"""Generate assets/argus.ico — the ARGUS taskbar / app icon.

The icon is drawn programmatically (no binary blobs in the repo), matching the
Hunter-Deck HUD: an obsidian hex sigil with a molten-amber reticle + 'A'.

    pip install pillow
    python build_icon.py        # -> assets/argus.ico  (+ assets/argus.png)
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT_DIR = ROOT / "assets"

BG = (12, 16, 25, 255)        # obsidian
RING = (18, 26, 40, 255)
AMBER = (255, 157, 47, 255)   # XP amber
AMBER2 = (255, 202, 85, 255)
CYAN = (47, 227, 207, 255)


def _hexagon(cx, cy, r):
    # pointy-top hexagon matching the panel sigil
    import math
    pts = []
    for i in range(6):
        a = math.radians(60 * i - 90)
        pts.append((cx + r * math.cos(a), cy + r * math.sin(a)))
    return pts


def draw(size: int):
    from PIL import Image, ImageDraw
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    s = size
    cx = cy = s / 2

    # outer amber hex ring + obsidian fill
    d.polygon(_hexagon(cx, cy, s * 0.46), fill=AMBER)
    d.polygon(_hexagon(cx, cy, s * 0.42), fill=BG)
    d.polygon(_hexagon(cx, cy, s * 0.40), outline=RING, width=max(1, s // 64))

    # reticle
    lw = max(1, s // 40)
    d.ellipse((s * 0.30, s * 0.30, s * 0.70, s * 0.70), outline=CYAN, width=lw)
    d.ellipse((s * 0.455, s * 0.455, s * 0.545, s * 0.545), fill=AMBER2)
    for dx, dy in ((0, -1), (0, 1), (-1, 0), (1, 0)):
        x0 = cx + dx * s * 0.34 - (lw if dx else 0)
        y0 = cy + dy * s * 0.34 - (lw if dy else 0)
        x1 = cx + dx * s * 0.24 + (lw if dx else 0)
        y1 = cy + dy * s * 0.24 + (lw if dy else 0)
        d.line((x0, y0, x1, y1), fill=CYAN, width=lw)
    return img


def main() -> None:
    try:
        from PIL import Image  # noqa: F401
    except ImportError:
        raise SystemExit("Pillow required:  pip install pillow")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sizes = [16, 24, 32, 48, 64, 128, 256]
    imgs = [draw(sz) for sz in sizes]
    ico = OUT_DIR / "argus.ico"
    imgs[-1].save(ico, format="ICO", sizes=[(sz, sz) for sz in sizes])
    imgs[-1].save(OUT_DIR / "argus.png", format="PNG")
    print(f"wrote {ico}  ({', '.join(str(s) for s in sizes)} px)")
    print(f"wrote {OUT_DIR / 'argus.png'}")


if __name__ == "__main__":
    main()
