"""Render assets/strata.ico from the logo: a 5x5 grid of cells, rows stepping from dark to
light, one white finding cell. Each size is drawn on whole pixels so small icons stay crisp.

Usage: python assets/make_icon.py
"""

from pathlib import Path

from PIL import Image, ImageDraw

GROUND = (0x23, 0x23, 0x23, 255)
ROWS = [(0x3A,) * 3, (0x4A,) * 3, (0x5A,) * 3, (0x6E,) * 3, (0x8C,) * 3]
FINDING = (1, 3)  # row, column of the white cell
SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]


def render(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    radius = max(1, round(size * 0.06))
    draw.rounded_rectangle((0, 0, size - 1, size - 1), radius=radius, fill=GROUND)
    pad = max(1, round(size * 0.18)) if size >= 24 else 1
    gap = max(1, round(size * 0.025))
    cell = (size - 2 * pad - 4 * gap) // 5
    grid = 5 * cell + 4 * gap
    origin = (size - grid) // 2
    for r, tone in enumerate(ROWS):
        for c in range(5):
            x = origin + c * (cell + gap)
            y = origin + r * (cell + gap)
            fill = (255, 255, 255, 255) if (r, c) == FINDING else (*tone, 255)
            draw.rectangle((x, y, x + cell - 1, y + cell - 1), fill=fill)
    return img


def main() -> None:
    out = Path(__file__).with_name("strata.ico")
    images = [render(s) for s in SIZES]
    images[-1].save(out, format="ICO", sizes=[(s, s) for s in SIZES], append_images=images[:-1])
    print(out)


if __name__ == "__main__":
    main()
