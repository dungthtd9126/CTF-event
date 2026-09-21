#!/usr/bin/env python3
"""Build adversarial submissions for the Decent Normally Bedbug challenge."""

from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path
import numpy as np
import requests
from PIL import Image, ImageDraw, ImageFont


DEFAULT_SERVER = "https://decent-normally-bedbug.ngrok-free.app"
EPSILON = 16
FONT_CANDIDATES = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf",
    "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
)


@dataclass(frozen=True)
class Assignment:
    assignment_id: str
    expected_images: list[str]
    target_prompts: dict[str, str]


def load_assignment(path: Path) -> Assignment:
    data = json.loads(path.read_text(encoding="utf-8"))
    return Assignment(
        assignment_id=data["assignment_id"],
        expected_images=data["expected_images"],
        target_prompts=data["target_prompts"],
    )


def locate_font() -> str:
    for candidate in FONT_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    if shutil.which("fc-match"):
        result = subprocess.run(
            ["fc-match", "-f", "%{file}\n", "DejaVu Sans:style=Bold"],
            check=True,
            capture_output=True,
            text=True,
        )
        candidate = result.stdout.splitlines()[0]
        if Path(candidate).is_file():
            return candidate
    raise RuntimeError("No bold TrueType font found")


def text_box(
    draw: ImageDraw.ImageDraw,
    text: str,
    font: ImageFont.FreeTypeFont,
    stroke_width: int,
) -> tuple[int, int]:
    box = draw.textbbox((0, 0), text, font=font, stroke_width=stroke_width)
    return box[2] - box[0], box[3] - box[1]


def wrap_words(
    draw: ImageDraw.ImageDraw,
    text: str,
    font: ImageFont.FreeTypeFont,
    max_width: int,
    stroke_width: int,
) -> list[str]:
    words = text.upper().split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = word if not current else f"{current} {word}"
        if not current or text_box(draw, candidate, font, stroke_width)[0] <= max_width:
            current = candidate
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


def fit_prompt(
    size: tuple[int, int],
    prompt: str,
    font_path: str,
) -> tuple[ImageFont.FreeTypeFont, list[str], int, int]:
    width, height = size
    scratch = Image.new("L", size)
    draw = ImageDraw.Draw(scratch)
    margin = max(5, width // 40)

    for font_size in range(min(30, height // 5), 10, -1):
        stroke_width = max(1, font_size // 12)
        font = ImageFont.truetype(font_path, font_size)
        lines = wrap_words(draw, prompt, font, width - 2 * margin, stroke_width)
        line_gap = max(3, font_size // 4)
        heights = [text_box(draw, line, font, stroke_width)[1] for line in lines]
        total_height = sum(heights) + line_gap * max(0, len(lines) - 1)
        if total_height <= height - 2 * margin:
            return font, lines, line_gap, stroke_width

    font = ImageFont.truetype(font_path, 11)
    return font, wrap_words(draw, prompt, font, width - 2 * margin, 1), 3, 1


def alpha_text_image(original: Image.Image, prompt: str) -> Image.Image:
    """Create an alpha/RGB hybrid caption that stays inside the RGB budget."""
    rgb = original.convert("RGB")
    alpha = Image.new("L", rgb.size, 0)
    draw = ImageDraw.Draw(alpha)
    font, lines, line_gap, stroke_width = fit_prompt(rgb.size, prompt, locate_font())
    dimensions = [text_box(draw, line, font, stroke_width) for line in lines]
    total_height = sum(height for _, height in dimensions) + line_gap * (len(lines) - 1)
    y = max(2, (rgb.height - total_height) // 2)

    for line, (width, height) in zip(lines, dimensions):
        x = max(1, (rgb.width - width) // 2)
        draw.text(
            (x, y),
            line,
            font=font,
            fill=255,
            stroke_width=stroke_width,
            stroke_fill=255,
        )
        y += height + line_gap

    original_array = np.asarray(rgb, dtype=np.int16)
    text_mask = np.asarray(alpha) > 0
    # If alpha is honored, this becomes textured dark text on a clean transparent
    # canvas. If alpha is dropped, the legal +/-16 RGB shifts still form text.
    candidate_array = np.clip(original_array + EPSILON, 0, 255)
    candidate_array[text_mask] = np.clip(
        original_array[text_mask] - EPSILON,
        0,
        255,
    )
    rgba = Image.fromarray(candidate_array.astype(np.uint8), mode="RGB")
    rgba.putalpha(alpha)
    return rgba


def composite_rgba(image: Image.Image, background: str) -> Image.Image:
    canvas = Image.new("RGB", image.size, background)
    canvas.paste(image, mask=image.getchannel("A"))
    return canvas


def png_bytes(image: Image.Image) -> bytes:
    output = io.BytesIO()
    image.save(output, format="PNG", optimize=False, compress_level=6)
    return output.getvalue()


def max_rgb_diff(original: Image.Image, candidate: Image.Image) -> int:
    left = np.asarray(original.convert("RGB"), dtype=np.int16)
    right = np.asarray(candidate.convert("RGB"), dtype=np.int16)
    return int(np.abs(left - right).max())


def build_alpha_submission(
    assignment: Assignment,
    data_dir: Path,
    output_zip: Path,
    preview_dir: Path | None,
) -> None:
    if preview_dir:
        preview_dir.mkdir(parents=True, exist_ok=True)

    manifest: list[dict[str, object]] = []
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for index, name in enumerate(assignment.expected_images):
            source = data_dir / name
            prompt = assignment.target_prompts[name]
            with Image.open(source) as image:
                original = image.convert("RGB")
                candidate = alpha_text_image(original, prompt)
                diff = max_rgb_diff(original, candidate)
                if diff > EPSILON:
                    raise RuntimeError(f"{name}: RGB diff is {diff}, exceeds {EPSILON}")
                archive.writestr(name, png_bytes(candidate))

                if preview_dir:
                    stem = f"{index:02d}_{Path(name).stem}"
                    composite_rgba(candidate, "white").save(preview_dir / f"{stem}_white.png")
                    composite_rgba(candidate, "black").save(preview_dir / f"{stem}_black.png")

            manifest.append(
                {
                    "name": name,
                    "prompt": prompt,
                    "mode": candidate.mode,
                    "rgb_max_diff": diff,
                }
            )

    output_zip.with_suffix(".manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"[+] wrote {output_zip} with {len(manifest)} RGBA images")
    print(f"[+] verified RGB max diff <= {EPSILON} for every image")


def validate_zip(assignment: Assignment, data_dir: Path, zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path) as archive:
        names = archive.namelist()
        if names != assignment.expected_images:
            raise RuntimeError("ZIP entries do not exactly match expected_images in order")

        modes: dict[str, int] = {}
        maximum = 0
        for name in names:
            with Image.open(data_dir / name) as original:
                with Image.open(io.BytesIO(archive.read(name))) as candidate:
                    candidate.load()
                    modes[candidate.mode] = modes.get(candidate.mode, 0) + 1
                    maximum = max(maximum, max_rgb_diff(original, candidate))
        print(f"[+] ZIP valid: {len(names)} images, modes={modes}, RGB max diff={maximum}")


def submit(server: str, token: str, assignment: Assignment, zip_path: Path) -> dict:
    if not token:
        raise RuntimeError("Set TEAM_TOKEN or pass --token before submitting")
    with zip_path.open("rb") as handle:
        response = requests.post(
            f"{server.rstrip('/')}/submit",
            params={"assignment_id": assignment.assignment_id},
            headers={"X-Team-Token": token},
            files={"file": (zip_path.name, handle, "application/zip")},
            timeout=600,
        )
    print(f"[*] HTTP {response.status_code}")
    try:
        result = response.json()
    except requests.JSONDecodeError:
        print(response.text)
        response.raise_for_status()
        raise
    print(json.dumps(result, indent=2, ensure_ascii=False))
    result_path = zip_path.with_suffix(".result.json")
    result_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"[+] wrote {result_path}")
    response.raise_for_status()
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assignment", type=Path, default=Path("assignment.json"))
    parser.add_argument("--data-dir", type=Path, default=Path("Data"))
    parser.add_argument("--out", type=Path, default=Path("submission_alpha.zip"))
    parser.add_argument("--preview-dir", type=Path)
    parser.add_argument("--server", default=os.environ.get("CHALLENGE_URL", DEFAULT_SERVER))
    parser.add_argument("--token", default=os.environ.get("TEAM_TOKEN", ""))
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--submit", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    assignment = load_assignment(args.assignment)
    build_alpha_submission(assignment, args.data_dir, args.out, args.preview_dir)
    if args.validate or args.submit:
        validate_zip(assignment, args.data_dir, args.out)
    if args.submit:
        submit(args.server, args.token, assignment, args.out)


if __name__ == "__main__":
    main()
