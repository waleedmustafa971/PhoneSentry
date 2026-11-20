"""Generates the PhoneSentry logo (PNG + multi-size ICO) with Pillow.

Run:  .venv\\Scripts\\python.exe tools\\make_logo.py
"""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets"
S = 1024  # draw large, downsample for anti-aliasing


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(len(a)))


def shield_path(cx, top, w, h):
    """Polygon approximating a classic shield outline."""
    pts = []
    left, right = cx - w / 2, cx + w / 2
    # top edge with slight inward curve at the shoulders
    steps = 40
    for i in range(steps + 1):
        t = i / steps
        x = left + (right - left) * t
        dip = 0.06 * h * (1 - (2 * t - 1) ** 2)  # gentle center dip
        pts.append((x, top + dip * 0.35))
    # right side down to the point
    for i in range(1, steps + 1):
        t = i / steps
        x = right - (w / 2) * (t ** 1.8)
        y = top + h * 0.38 + (h * 0.62) * (t ** 0.9) if t > 0 else top
        if t < 0.0001:
            y = top
        pts.append((x, top + h * 0.05 + (y - top - h * 0.05) if t else top))
    # left side back up (mirror)
    right_side = pts[steps + 1:]
    for x, y in reversed(right_side[:-1]):
        pts.append((cx - (x - cx), y))
    return pts


def build():
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))

    # --- shield body with vertical gradient
    grad = Image.new("RGBA", (S, S))
    gd = ImageDraw.Draw(grad)
    top_c, bot_c = (34, 211, 238, 255), (37, 99, 235, 255)  # cyan -> blue
    for y in range(S):
        gd.line([(0, y), (S, y)], fill=lerp(top_c, bot_c, y / S))
    mask = Image.new("L", (S, S), 0)
    shield = shield_path(S / 2, 70, 820, 900)
    ImageDraw.Draw(mask).polygon(shield, fill=255)
    mask = mask.filter(ImageFilter.GaussianBlur(1.2))

    # drop shadow
    shadow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    sm = mask.filter(ImageFilter.GaussianBlur(18))
    shadow.paste((8, 20, 50, 140), (0, 14), sm)
    img = Image.alpha_composite(img, shadow)
    img.paste(grad, (0, 0), mask)

    # inner rim
    d = ImageDraw.Draw(img)
    inner = shield_path(S / 2, 120, 700, 790)
    d.line(inner + [inner[0]], fill=(255, 255, 255, 70), width=10, joint="curve")

    # --- phone silhouette
    pw, ph = 330, 540
    px0, py0 = S / 2 - pw / 2, 230
    d.rounded_rectangle([px0, py0, px0 + pw, py0 + ph], radius=56, fill=(11, 18, 38, 255))
    d.rounded_rectangle([px0 + 22, py0 + 60, px0 + pw - 22, py0 + ph - 60], radius=20,
                        fill=(17, 30, 62, 255))
    d.rounded_rectangle([S / 2 - 40, py0 + 24, S / 2 + 40, py0 + 36], radius=6,
                        fill=(60, 80, 120, 255))

    # --- scan beam across the screen
    beam_y = py0 + ph * 0.42
    beam = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    bd = ImageDraw.Draw(beam)
    for i in range(60):
        a = int(110 * (1 - i / 60))
        bd.line([(px0 + 22, beam_y + i), (px0 + pw - 22, beam_y + i)], fill=(34, 211, 238, a))
    bd.line([(px0 + 10, beam_y), (px0 + pw - 10, beam_y)], fill=(165, 243, 252, 255), width=8)
    beam = beam.filter(ImageFilter.GaussianBlur(1.5))
    img = Image.alpha_composite(img, beam)
    d = ImageDraw.Draw(img)

    # --- check mark badge
    bx, by, br = S / 2 + 150, py0 + ph - 40, 120
    d.ellipse([bx - br - 10, by - br - 10, bx + br + 10, by + br + 10], fill=(11, 18, 38, 255))
    d.ellipse([bx - br, by - br, bx + br, by + br], fill=(16, 185, 129, 255))
    d.line([(bx - 55, by + 2), (bx - 12, by + 45), (bx + 60, by - 45)],
           fill=(255, 255, 255, 255), width=30, joint="curve")

    OUT.mkdir(exist_ok=True)
    img.save(OUT / "logo-1024.png")
    img.resize((256, 256), Image.LANCZOS).save(OUT / "logo.png")
    img.resize((96, 96), Image.LANCZOS).save(OUT / "logo-96.png")
    img.save(OUT / "logo.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48),
                                     (64, 64), (128, 128), (256, 256)])
    print("wrote", OUT / "logo.ico")


if __name__ == "__main__":
    build()
