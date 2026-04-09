#!/usr/bin/env python3
"""
generate-android-icons.py
─────────────────────────

Generates BMSecResearch's Android launcher icons (legacy + adaptive)
at every required density. The visual design mirrors the in-app brand
mark in `src/App.svelte` — a hollow accent-orange square with a small
accent dot at the upper-right corner and "BM" centered inside.

Requires Pillow only (no ImageMagick / Inkscape).

Output:
    src-tauri/gen/android/app/src/main/res/mipmap-{mdpi,hdpi,xhdpi,xxhdpi,xxxhdpi}/
        ic_launcher.png             # legacy square icon (full bleed)
        ic_launcher_round.png       # legacy circular icon
        ic_launcher_foreground.png  # adaptive icon foreground layer
    src-tauri/gen/android/app/src/main/res/values/colors.xml
        ic_launcher_background      # adaptive icon background colour
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont, ImageFilter

# ── Design tokens (match src/app.css) ────────────────────────────────
BG_COLOR = (7, 8, 10, 255)        # var(--bg-primary)  #07080a
ACCENT = (255, 140, 26, 255)       # var(--accent)      #ff8c1a
ACCENT_GLOW = (255, 140, 26, 64)   # var(--accent-glow) (low-alpha for glow)


@dataclass
class Density:
    name: str          # mdpi / hdpi / xhdpi / etc
    legacy_px: int     # square icon size in pixels
    adaptive_px: int   # adaptive icon foreground/background size (108dp at this density)


# Standard Android launcher icon densities. The legacy icons are square
# at the listed pixel size; the adaptive icons (Android 8+) are 108dp on
# every side, scaled to the same density bucket.
DENSITIES = [
    Density("mdpi",    48, 108),
    Density("hdpi",    72, 162),
    Density("xhdpi",   96, 216),
    Density("xxhdpi", 144, 324),
    Density("xxxhdpi", 192, 432),
]

# The repo root, resolved from this script's location
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
RES_DIR = REPO_ROOT / "src-tauri" / "gen" / "android" / "app" / "src" / "main" / "res"


def find_mono_font(target_size: int) -> ImageFont.FreeTypeFont:
    """Locate a monospace font on the system that scales cleanly. Falls
    back to PIL's default bitmap font if none of the candidates exist."""
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Bold.ttf",
        "/usr/share/fonts/TTF/DejaVuSansMono-Bold.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono-Bold.ttf",
        "/System/Library/Fonts/Menlo.ttc",
    ]
    for path in candidates:
        if os.path.isfile(path):
            return ImageFont.truetype(path, target_size)
    print("WARN: no TTF monospace font found, using PIL default", file=sys.stderr)
    return ImageFont.load_default()


def draw_brand_mark(
    canvas_size: int,
    *,
    background: str,           # "transparent" | "square" | "circle"
    mark_ratio: float,
    border_thickness_ratio: float = 0.045,
    corner_radius_ratio: float = 0.090,
    show_dot: bool = True,
) -> Image.Image:
    """Draw the BMSecResearch brand mark on a square canvas.

    Mirrors the in-app brand mark in App.svelte but with mask-safe
    geometry: the brand mark fits inside the inscribed circle of the
    canvas so any Android adaptive-icon mask shape (circle, squircle,
    teardrop, rounded-square) renders cleanly without cropping the
    mark or its decorative dot.

    Args:
        canvas_size: Width/height of the output image in pixels.
        background:  "transparent" — no fill (adaptive icon foreground)
                     "square"      — full bg colour (legacy square icon)
                     "circle"      — bg colour clipped to a centred
                                     circle (legacy round icon for
                                     Android <= 7 launchers without
                                     adaptive-icon support)
        mark_ratio:  Fraction of the canvas the brand-mark square
                     occupies. Must be small enough that the entire
                     square + decorative dot fit inside the canvas's
                     inscribed circle:
                       - 0.45 for adaptive icons (Android safe zone is
                         the inner 66% of canvas, so the inscribed
                         circle of the safe zone has radius 33%; a
                         centred 45%-wide square has its corners at
                         √2 × 22.5% = 31.8% from centre, just inside)
                       - 0.65 for legacy round icons (centred square
                         must fit inside the canvas's inscribed circle
                         of radius 50%; corners at √2 × 32.5% = 46%,
                         leaving 4% margin)
                       - 0.78 for legacy square icons (no mask, fills
                         most of the canvas)
        show_dot:    Whether to draw the decorative accent dot at the
                     square's top-right corner.
    """
    # ── Background layer ────────────────────────────────────────────
    img = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
    if background == "square":
        ImageDraw.Draw(img).rectangle((0, 0, canvas_size, canvas_size), fill=BG_COLOR)
    elif background == "circle":
        ImageDraw.Draw(img).ellipse(
            (0, 0, canvas_size - 1, canvas_size - 1), fill=BG_COLOR
        )
    # transparent → leave the canvas alone

    draw = ImageDraw.Draw(img, "RGBA")

    # ── Compute brand mark geometry ────────────────────────────────
    mark_size = int(canvas_size * mark_ratio)
    margin = (canvas_size - mark_size) // 2
    border_thickness = max(2, int(canvas_size * border_thickness_ratio))
    corner_radius = max(2, int(canvas_size * corner_radius_ratio))

    # ── Subtle accent glow behind the square ───────────────────────
    # Soft amber halo that mirrors the in-app `box-shadow: 0 0 8px
    # var(--accent-glow)`. Blurred so it bleeds slightly past the
    # square edges without disturbing the mask boundary.
    glow_pad = int(canvas_size * 0.035)
    glow_layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
    glow_draw = ImageDraw.Draw(glow_layer)
    glow_draw.rounded_rectangle(
        (
            margin - glow_pad,
            margin - glow_pad,
            margin + mark_size + glow_pad,
            margin + mark_size + glow_pad,
        ),
        radius=corner_radius + glow_pad,
        fill=ACCENT_GLOW,
    )
    glow_layer = glow_layer.filter(ImageFilter.GaussianBlur(radius=canvas_size * 0.022))
    img = Image.alpha_composite(img, glow_layer)
    draw = ImageDraw.Draw(img, "RGBA")

    # ── Hollow rounded square (border, no fill) ────────────────────
    draw.rounded_rectangle(
        (
            margin,
            margin,
            margin + mark_size - 1,
            margin + mark_size - 1,
        ),
        radius=corner_radius,
        outline=ACCENT,
        width=border_thickness,
    )

    # ── Decorative accent dot ──────────────────────────────────────
    # Positioned AT the square's top-right corner (not OUTSIDE it as
    # in the in-app version) so the entire dot stays within the
    # bounding box of the brand mark and doesn't get cropped by any
    # adaptive-icon mask shape.
    if show_dot:
        dot_radius = max(3, int(canvas_size * 0.030))
        dot_cx = margin + mark_size - dot_radius
        dot_cy = margin + dot_radius
        draw.ellipse(
            (
                dot_cx - dot_radius,
                dot_cy - dot_radius,
                dot_cx + dot_radius,
                dot_cy + dot_radius,
            ),
            fill=ACCENT,
        )

    # ── "BM" text centered inside the square ───────────────────────
    # Pick a font size that fills ~50% of the inner square width.
    target_text_height = int(mark_size * 0.50)
    font = find_mono_font(target_text_height)
    text = "BM"
    bbox = draw.textbbox((0, 0), text, font=font)
    text_w = bbox[2] - bbox[0]
    text_h = bbox[3] - bbox[1]
    text_x = margin + (mark_size - text_w) // 2 - bbox[0]
    text_y = margin + (mark_size - text_h) // 2 - bbox[1]
    draw.text((text_x, text_y), text, font=font, fill=ACCENT)

    return img


def write_png(img: Image.Image, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path, "PNG", optimize=True)
    print(f"  wrote {path.relative_to(REPO_ROOT)} ({img.size[0]}x{img.size[1]})")


def make_circular(img: Image.Image) -> Image.Image:
    """Apply a circular alpha mask to a square image. Kept as a utility
    even though we now draw the round legacy icon directly on a circular
    background — useful for one-off masking if needed in the future."""
    mask = Image.new("L", img.size, 0)
    ImageDraw.Draw(mask).ellipse((0, 0, img.size[0] - 1, img.size[1] - 1), fill=255)
    out = Image.new("RGBA", img.size, (0, 0, 0, 0))
    out.paste(img, (0, 0), mask)
    return out


def write_colors_xml() -> None:
    """Write the adaptive icon background colour into res/values/colors.xml.
    The Tauri scaffold doesn't put one there by default, so we create or
    extend it."""
    colors_path = RES_DIR / "values" / "colors.xml"
    colors_path.parent.mkdir(parents=True, exist_ok=True)
    bg_hex = "#{:02x}{:02x}{:02x}".format(*BG_COLOR[:3])
    content = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<resources>\n"
        f'    <color name="ic_launcher_background">{bg_hex}</color>\n'
        "</resources>\n"
    )
    colors_path.write_text(content)
    print(f"  wrote {colors_path.relative_to(REPO_ROOT)}")


def write_adaptive_icon_xml() -> None:
    """Write the adaptive icon definition (mipmap-anydpi-v26/ic_launcher.xml).
    This points the system at the foreground PNG and the background colour."""
    for name in ("ic_launcher.xml", "ic_launcher_round.xml"):
        path = RES_DIR / "mipmap-anydpi-v26" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        content = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n'
            '    <background android:drawable="@color/ic_launcher_background" />\n'
            '    <foreground android:drawable="@mipmap/ic_launcher_foreground" />\n'
            "</adaptive-icon>\n"
        )
        path.write_text(content)
        print(f"  wrote {path.relative_to(REPO_ROOT)}")


def remove_old_drawables() -> None:
    """Remove the placeholder vector drawables Tauri generates so the
    adaptive-icon XML can resolve to our PNG/colour assets cleanly."""
    for old in [
        RES_DIR / "drawable" / "ic_launcher_background.xml",
        RES_DIR / "drawable-v24" / "ic_launcher_foreground.xml",
    ]:
        if old.exists():
            old.unlink()
            print(f"  removed {old.relative_to(REPO_ROOT)}")


def main() -> int:
    if not RES_DIR.exists():
        print(f"ERROR: Android res dir not found at {RES_DIR}", file=sys.stderr)
        print("Run `cargo tauri android init` first.", file=sys.stderr)
        return 1

    print(f"Generating Android launcher icons under {RES_DIR.relative_to(REPO_ROOT)}")
    print()

    # Remove conflicting Tauri-generated drawables
    remove_old_drawables()

    # Adaptive icon background colour
    write_colors_xml()

    # Adaptive icon XML definitions
    write_adaptive_icon_xml()

    # Per-density assets
    #
    # Three icon variants per density, each with mask-safe geometry:
    #
    #   ic_launcher.png            — legacy SQUARE icon. Used by older
    #                                Android (≤7) and as a fallback by
    #                                some launchers. Brand mark fills
    #                                ~78% of the canvas because there's
    #                                no mask cropping.
    #
    #   ic_launcher_round.png      — legacy ROUND icon. Same older-Android
    #                                target. Drawn directly on a circular
    #                                background (NOT by masking the
    #                                square version) and the brand mark
    #                                is sized to fit inside the canvas's
    #                                inscribed circle so corners aren't
    #                                clipped.
    #
    #   ic_launcher_foreground.png — adaptive icon foreground (Android 8+).
    #                                108dp canvas with a 66dp safe zone.
    #                                The brand mark fits inside an
    #                                inscribed circle of the safe zone
    #                                so any mask shape (circle, squircle,
    #                                teardrop, rounded-square, etc.)
    #                                renders cleanly. Background is
    #                                transparent — Android composites
    #                                the foreground over the background
    #                                colour from `colors.xml`.
    for d in DENSITIES:
        mipmap = RES_DIR / f"mipmap-{d.name}"

        # Legacy square — full bleed background, brand mark at 0.78.
        # No decorative dot at icon scale: the dot reads as visual
        # noise / a stuck pixel on a small launcher icon. Keep the dot
        # only in the in-app brand mark where it pulses as a "live"
        # indicator.
        square = draw_brand_mark(
            d.legacy_px,
            background="square",
            mark_ratio=0.78,
            show_dot=False,
        )
        write_png(square, mipmap / "ic_launcher.png")

        # Legacy round — circular background, brand mark at 0.65 to fit
        # inside the inscribed square of the canvas circle.
        round_icon = draw_brand_mark(
            d.legacy_px,
            background="circle",
            mark_ratio=0.65,
            show_dot=False,
        )
        write_png(round_icon, mipmap / "ic_launcher_round.png")

        # Adaptive foreground — transparent bg, brand mark at 0.45 so
        # the entire mark fits inside an inscribed circle of the 66dp
        # adaptive-icon safe zone. Any mask shape will display the
        # full mark without cropping.
        foreground = draw_brand_mark(
            d.adaptive_px,
            background="transparent",
            mark_ratio=0.45,
            show_dot=False,
        )
        write_png(foreground, mipmap / "ic_launcher_foreground.png")

    print()
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
