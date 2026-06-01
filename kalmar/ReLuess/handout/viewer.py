#!/usr/bin/env python3
"""Totally cool AI viewer! My AI model also gave the following information below but I dont understand it.

Loads a .pt state dict, extracts the first-layer weight matrix W1 and bias b1,
sorts rows by pre-activation at x=0.5 (ascending) to recover the original row
ordering, normalises to [0, 255], and writes a PGM (Portable GrayMap) image file.

Usage:
    python viewer.py model.pt            # writes flag.pgm
    python viewer.py model.pt out.pgm    # custom output path
"""
import sys

import torch
import numpy as np


def load_weights(path):
    """Load W1 and b1 from a state dict."""
    sd = torch.load(path, weights_only=True, map_location="cpu")
    W1 = sd["fc1.weight"].numpy()  # (d_hidden, d_in)
    b1 = sd["fc1.bias"].numpy()    # (d_hidden,)
    return W1, b1


def sort_rows(W1, b1):
    """Sort rows of W1 by pre-activation at x=0.5 to recover original row ordering.

    The model is constructed so that W1[j] . 0.5 + b1[j] = 0.001*j, meaning
    the content-dependent terms cancel and only the row index remains.
    """
    pre_act = W1 @ np.full(W1.shape[1], 0.5) + b1
    order = np.argsort(pre_act)
    return W1[order]


def to_uint8(img):
    """Normalise a 2-D array to [0, 255] uint8."""
    lo, hi = img.min(), img.max()
    if hi - lo < 1e-12:
        return np.zeros_like(img, dtype=np.uint8)
    scaled = (img - lo) / (hi - lo) * 255.0
    return scaled.round().astype(np.uint8)


def scale_horizontal(img, target_w):
    """Nearest-neighbor horizontal scaling to *target_w* columns."""
    src_w = img.shape[1]
    indices = np.linspace(0, src_w - 1, target_w).round().astype(int)
    return img[:, indices]


def write_pgm(path, img_u8):
    """Write a P2 (text) PGM file — zero external dependencies."""
    h, w = img_u8.shape
    with open(path, "w") as f:
        f.write(f"P2\n{w} {h}\n255\n")
        for row in img_u8:
            f.write(" ".join(str(int(v)) for v in row) + "\n")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} model.pt [output.pgm]")
        sys.exit(1)

    model_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else "flag.pgm"

    W1, b1 = load_weights(model_path)
    W1_sorted = sort_rows(W1, b1)
    img = to_uint8(W1_sorted)

    PGM_WIDTH = 1024
    img_scaled = scale_horizontal(img, PGM_WIDTH)
    write_pgm(out_path, img_scaled)
    print(f"Wrote {out_path} ({img_scaled.shape[1]}x{img_scaled.shape[0]})")


if __name__ == "__main__":
    main()
