#!/usr/bin/env python3
"""
Solver for the limited-submission image perturbation challenge.

Attack idea:
  Render the server-provided target prompt as low-contrast OCR text over the
  original image, while clipping every RGB channel to the allowed L_inf bound
  (default 16/255). The ZIP entries keep the exact expected names, but images
  are encoded losslessly as PNG bytes to avoid JPEG recompression breaking the
  diff check.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import numpy as np
import requests
from PIL import Image, ImageDraw, ImageFont

DEFAULT_SERVER = "https://decent-normally-bedbug.ngrok-free.app/"
DEFAULT_TOKEN = "ctf_token_team1_xyz"
GOOGLE_DRIVE_ID = "1KQm_csxxHlji8XISd1QKEXuY7EOKwFLi"
DEFAULT_EPS = 16  # 16/255 == 0.062745098...
VALID_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".webp"}


@dataclass
class Assignment:
    assignment_id: str
    expected_images: List[str]
    target_prompts: Dict[str, str]


def die(msg: str, code: int = 1) -> None:
    print(f"[-] {msg}", file=sys.stderr)
    raise SystemExit(code)


def headers(token: str) -> Dict[str, str]:
    return {"X-Team-Token": token}


def norm_server(url: str) -> str:
    return url.rstrip("/")


def check_status(server: str, token: str) -> dict:
    r = requests.get(f"{norm_server(server)}/status", headers=headers(token), timeout=20)
    r.raise_for_status()
    data = r.json()
    print("[*] status:", json.dumps(data, indent=2, ensure_ascii=False))
    return data


def request_assignment(server: str, token: str, out_json: Path) -> Assignment:
    r = requests.post(f"{norm_server(server)}/assignment", headers=headers(token), timeout=60)
    r.raise_for_status()
    data = r.json()
    out_json.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[+] saved assignment JSON to {out_json}")
    return parse_assignment(data)


def parse_assignment(data: dict) -> Assignment:
    aid = data.get("assignment_id") or ""
    expected = data.get("expected_images") or []
    targets = data.get("target_prompts") or {}
    if not aid:
        die("assignment JSON has no assignment_id")
    if not expected:
        die("assignment JSON has no expected_images")
    missing = [name for name in expected if name not in targets]
    if missing:
        die(f"target_prompts is missing {len(missing)} expected images, first={missing[:3]!r}")
    return Assignment(aid, list(expected), dict(targets))


def load_assignment(path: Path) -> Assignment:
    return parse_assignment(json.loads(path.read_text(encoding="utf-8")))


def _google_confirm_token(resp: requests.Response) -> Optional[str]:
    for k, v in resp.cookies.items():
        if k.startswith("download_warning"):
            return v
    # Newer Google Drive sometimes returns an HTML interstitial with confirm=...
    ctype = resp.headers.get("content-type", "")
    if "text/html" in ctype.lower():
        text = resp.text
        m = re.search(r"confirm=([0-9A-Za-z_\-]+)", text)
        if m:
            return m.group(1)
        m = re.search(r'name="confirm"\s+value="([0-9A-Za-z_\-]+)"', text)
        if m:
            return m.group(1)
    return None


def download_from_google_drive(file_id: str, out_path: Path) -> None:
    """Small public-GDrive downloader; no external gdown dependency."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    sess = requests.Session()
    base = "https://drive.google.com/uc"
    params = {"export": "download", "id": file_id}
    print(f"[*] downloading Google Drive file {file_id} -> {out_path}")
    resp = sess.get(base, params=params, stream=True, timeout=120)
    token = _google_confirm_token(resp)
    if token:
        params["confirm"] = token
        resp = sess.get(base, params=params, stream=True, timeout=120)
    resp.raise_for_status()

    ctype = resp.headers.get("content-type", "")
    if "text/html" in ctype.lower():
        # Preserve the HTML for debugging instead of silently writing a bogus archive.
        html_path = out_path.with_suffix(out_path.suffix + ".html")
        html_path.write_text(resp.text, encoding="utf-8", errors="ignore")
        die(
            f"Google returned HTML instead of the archive. Saved debug page to {html_path}. "
            "Download Data.7z manually from the challenge link and rerun with --data-archive."
        )

    total = 0
    with out_path.open("wb") as f:
        for chunk in resp.iter_content(1024 * 1024):
            if chunk:
                total += len(chunk)
                f.write(chunk)
    if total < 1024:
        die(f"downloaded file is suspiciously small: {total} bytes")
    print(f"[+] downloaded {total:,} bytes")


def extract_archive(archive: Path, out_dir: Path) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"[*] using existing extracted data at {out_dir}")
        return
    out_dir.mkdir(parents=True, exist_ok=True)
    suffix = archive.suffix.lower()
    if suffix == ".zip":
        with zipfile.ZipFile(archive) as z:
            z.extractall(out_dir)
        print(f"[+] extracted zip to {out_dir}")
        return
    if suffix == ".7z":
        for exe in ("7z", "7zz", "7za"):
            if shutil.which(exe):
                subprocess.run([exe, "x", "-y", str(archive), f"-o{out_dir}"], check=True)
                print(f"[+] extracted 7z to {out_dir}")
                return
        try:
            import py7zr  # type: ignore
        except ImportError:
            die("Need 7z/7zz/7za or `pip install py7zr` to extract Data.7z")
        with py7zr.SevenZipFile(archive, mode="r") as z:
            z.extractall(path=out_dir)
        print(f"[+] extracted 7z to {out_dir}")
        return
    die(f"unsupported archive format: {archive}")


def index_images(root: Path) -> Dict[str, Path]:
    idx: Dict[str, Path] = {}
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in VALID_IMAGE_EXTS:
            rel = p.relative_to(root).as_posix()
            idx.setdefault(rel, p)
            idx.setdefault(p.name, p)
    if not idx:
        die(f"no images found under {root}")
    return idx


def find_image(root: Path, idx: Dict[str, Path], expected_name: str) -> Path:
    # 1. Exact relative path under the extracted directory.
    direct = root / expected_name
    if direct.exists():
        return direct
    # 2. Exact relative key from recursive index.
    if expected_name in idx:
        return idx[expected_name]
    # 3. Basename match.
    base = Path(expected_name).name
    if base in idx:
        return idx[base]
    # 4. Case-insensitive fallback.
    low = expected_name.lower()
    for k, v in idx.items():
        if k.lower() == low or Path(k).name.lower() == Path(low).name:
            return v
    die(f"could not locate original image for expected entry {expected_name!r}")


def locate_font() -> str:
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf",
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
        "/Library/Fonts/Arial Bold.ttf",
        "C:/Windows/Fonts/arialbd.ttf",
    ]
    for c in candidates:
        if Path(c).exists():
            return c
    return ""  # PIL fallback


def font_at(path: str, size: int) -> ImageFont.ImageFont:
    if path:
        try:
            return ImageFont.truetype(path, size=size)
        except Exception:
            pass
    return ImageFont.load_default()


def text_size(draw: ImageDraw.ImageDraw, text: str, font: ImageFont.ImageFont) -> Tuple[int, int]:
    box = draw.textbbox((0, 0), text, font=font, stroke_width=0)
    return box[2] - box[0], box[3] - box[1]


def wrap_by_pixels(draw: ImageDraw.ImageDraw, text: str, font: ImageFont.ImageFont, max_width: int) -> List[str]:
    # Preserve short target prompt semantics, but break long text for OCR readability.
    words = text.split()
    if not words:
        return [""]
    lines: List[str] = []
    cur = words[0]
    for w in words[1:]:
        cand = cur + " " + w
        if text_size(draw, cand, font)[0] <= max_width:
            cur = cand
        else:
            lines.append(cur)
            cur = w
    lines.append(cur)
    return lines


def draw_line_with_box(
    draw_bg: ImageDraw.ImageDraw,
    draw_txt: ImageDraw.ImageDraw,
    xy: Tuple[int, int],
    line: str,
    font: ImageFont.ImageFont,
    width: int,
    pad: int,
    align: str = "center",
) -> int:
    x, y = xy
    tw, th = text_size(draw_txt, line, font)
    if align == "center":
        x = max(pad, (width - tw) // 2)
    elif align == "left":
        x = pad
    rect = (max(0, x - pad), max(0, y - pad // 2), min(width, x + tw + pad), y + th + pad)
    draw_bg.rectangle(rect, fill=255)
    # offset shadow edges slightly improve OCR under the L_inf cap.
    draw_txt.text((x + 1, y + 1), line, font=font, fill=160)
    draw_txt.text((x, y), line, font=font, fill=255)
    return y + th + pad + 2


def make_masks(w: int, h: int, prompt: str, variant: str, font_path: str) -> Tuple[Image.Image, Image.Image]:
    bg = Image.new("L", (w, h), 0)
    txt = Image.new("L", (w, h), 0)
    dbg = ImageDraw.Draw(bg)
    dt = ImageDraw.Draw(txt)

    clean_prompt = " ".join(prompt.strip().split())
    # Render the exact target, plus a natural caption prefix. Repetition helps OCR/VLMs.
    phrases = [clean_prompt, f"this image shows {clean_prompt}", f"caption: {clean_prompt}"]

    if variant == "banner":
        sizes = [max(18, min(w // 13, h // 7)), max(14, min(w // 22, h // 12))]
        y = max(4, h // 18)
        for s in sizes:
            font = font_at(font_path, s)
            lines = wrap_by_pixels(dt, phrases[0], font, int(w * 0.92))
            for line in lines[:4]:
                y = draw_line_with_box(dbg, dt, (0, y), line, font, w, max(3, s // 7))
        return bg, txt

    # Dense/default: big central caption + smaller repeated OCR cues.
    big_size = max(18, min(w // 11, h // 6))
    big_font = font_at(font_path, big_size)
    big_lines = wrap_by_pixels(dt, phrases[0], big_font, int(w * 0.88))[:5]
    line_h = max(text_size(dt, "Ag", big_font)[1] + big_size // 3, big_size)
    block_h = len(big_lines) * line_h
    y = max(4, (h - block_h) // 2)
    for line in big_lines:
        y = draw_line_with_box(dbg, dt, (0, y), line, big_font, w, max(3, big_size // 7))

    small_size = max(11, min(w // 34, h // 18))
    small_font = font_at(font_path, small_size)
    small_lines: List[str] = []
    for p in phrases:
        small_lines.extend(wrap_by_pixels(dt, p, small_font, int(w * 0.95)))
    small_lines = [s for s in small_lines if s]
    if not small_lines:
        small_lines = [clean_prompt]

    y = 4
    i = 0
    step = max(small_size + 7, 16)
    while y < h - step:
        line = small_lines[i % len(small_lines)]
        # Alternate slight x alignment by using full-width boxes; the exact text is centered.
        draw_line_with_box(dbg, dt, (0, y), line, small_font, w, max(2, small_size // 7))
        y += step * 2
        i += 1

    if variant == "tile":
        # Extra diagonal-ish repeated short words for models that crop/resize aggressively.
        med_size = max(13, min(w // 26, h // 15))
        med_font = font_at(font_path, med_size)
        lines = wrap_by_pixels(dt, phrases[-1], med_font, int(w * 0.75)) or [phrases[-1]]
        y = h // 8
        while y < h:
            xoff = (y // 3) % max(1, w // 4)
            for line in lines[:3]:
                tw, th = text_size(dt, line, med_font)
                x = min(max(2, xoff), max(2, w - tw - 2))
                rect = (max(0, x - 2), max(0, y - 2), min(w, x + tw + 3), min(h, y + th + 3))
                dbg.rectangle(rect, fill=255)
                dt.text((x, y), line, font=med_font, fill=255)
                y += med_size + 5
            y += med_size * 2

    return bg, txt


def perturb_image(im: Image.Image, prompt: str, eps: int = DEFAULT_EPS, variant: str = "dense") -> Image.Image:
    rgb = im.convert("RGB")
    arr = np.asarray(rgb).astype(np.int16)
    h, w = arr.shape[:2]
    font_path = locate_font()
    bg_mask_img, txt_mask_img = make_masks(w, h, prompt, variant, font_path)
    bg = np.asarray(bg_mask_img).astype(np.float32) / 255.0
    txt = np.asarray(txt_mask_img).astype(np.float32) / 255.0

    # Background boxes go darker, text goes brighter. Text pixels on a box become +eps,
    # box-only pixels become -eps, so local edge contrast can approach 32/255 while every
    # individual pixel remains within the 16/255 bound.
    delta = (-eps * bg + 2 * eps * txt)
    delta = np.clip(delta, -eps, eps).astype(np.int16)
    adv = np.clip(arr + delta[:, :, None], 0, 255).astype(np.uint8)

    maxdiff = int(np.max(np.abs(adv.astype(np.int16) - arr)))
    if maxdiff > eps:
        die(f"internal error: max diff {maxdiff} > eps {eps}")
    return Image.fromarray(adv, mode="RGB")


def save_png_bytes(im: Image.Image) -> bytes:
    bio = io.BytesIO()
    # PNG is crucial: JPEG recompression can exceed the allowed diff.
    im.save(bio, format="PNG", optimize=False, compress_level=6)
    return bio.getvalue()


def build_submission(data_dir: Path, assignment: Assignment, out_zip: Path, eps: int, variant: str) -> None:
    idx = index_images(data_dir)
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    print(f"[*] building {out_zip} with variant={variant}, eps={eps}")
    rows = []
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name in assignment.expected_images:
            src = find_image(data_dir, idx, name)
            prompt = assignment.target_prompts[name]
            with Image.open(src) as im:
                orig = im.convert("RGB")
                adv = perturb_image(orig, prompt, eps=eps, variant=variant)
                diff = int(np.max(np.abs(np.asarray(adv).astype(np.int16) - np.asarray(orig).astype(np.int16))))
                if diff > eps:
                    die(f"{name}: diff {diff} > eps {eps}")
                z.writestr(name, save_png_bytes(adv))
                rows.append((name, src.as_posix(), diff, prompt))
                print(f"  [+] {name}: src={src.name}, maxdiff={diff}, target={prompt!r}")
    manifest = out_zip.with_suffix(".manifest.json")
    manifest.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[+] wrote {out_zip}")
    print(f"[+] wrote {manifest}")


def submit(server: str, token: str, assignment_id: str, zip_path: Path) -> dict:
    with zip_path.open("rb") as f:
        files = {"file": (zip_path.name, f, "application/zip")}
        r = requests.post(
            f"{norm_server(server)}/submit",
            headers=headers(token),
            params={"assignment_id": assignment_id},
            files=files,
            timeout=360,
        )
    print(f"[*] submit HTTP {r.status_code}")
    try:
        data = r.json()
        print(json.dumps(data, indent=2, ensure_ascii=False))
    except Exception:
        print(r.text)
        r.raise_for_status()
        return {}
    r.raise_for_status()
    if data.get("passed"):
        print(f"\n[!!!] FLAG: {data.get('flag')}\n")
    return data


def ensure_data(args: argparse.Namespace) -> Path:
    data_dir = Path(args.data_dir)
    if data_dir.exists() and any(data_dir.rglob("*")):
        return data_dir

    archive = Path(args.data_archive) if args.data_archive else Path("Data.7z")
    if not archive.exists():
        download_from_google_drive(GOOGLE_DRIVE_ID, archive)
    extract_archive(archive, data_dir)
    return data_dir


def main() -> None:
    ap = argparse.ArgumentParser(description="Build and optionally submit a bounded OCR adversarial image ZIP.")
    ap.add_argument("--server", default=os.environ.get("CHALLENGE_URL", DEFAULT_SERVER))
    ap.add_argument("--token", default=os.environ.get("TEAM_TOKEN", DEFAULT_TOKEN))
    ap.add_argument("--assignment-json", default="assignment.json", help="Saved assignment JSON path")
    ap.add_argument("--new-assignment", action="store_true", help="Request a fresh assignment even if assignment JSON exists")
    ap.add_argument("--data-archive", default="", help="Path to Data.7z if already downloaded")
    ap.add_argument("--data-dir", default="Data", help="Extracted dataset directory")
    ap.add_argument("--out", default="submission.zip")
    ap.add_argument("--eps", type=int, default=DEFAULT_EPS)
    ap.add_argument("--variant", choices=["dense", "banner", "tile"], default="dense")
    ap.add_argument("--submit", action="store_true", help="Actually POST the ZIP to the server; costs one submission")
    ap.add_argument("--status", action="store_true", help="Check status before doing anything")
    args = ap.parse_args()

    if args.status:
        check_status(args.server, args.token)

    assignment_path = Path(args.assignment_json)
    if args.new_assignment or not assignment_path.exists():
        assignment = request_assignment(args.server, args.token, assignment_path)
    else:
        assignment = load_assignment(assignment_path)
        print(f"[*] loaded assignment {assignment.assignment_id} from {assignment_path}")

    data_dir = ensure_data(args)
    build_submission(data_dir, assignment, Path(args.out), args.eps, args.variant)

    print("\n[+] Ready. Inspect the ZIP if desired. To spend one server attempt, rerun with --submit or add --submit now.")
    if args.submit:
        submit(args.server, args.token, assignment.assignment_id, Path(args.out))


if __name__ == "__main__":
    main()
