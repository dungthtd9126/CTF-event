# Decent Normally Bedbug

## Category

Adversarial ML / misc.

## Challenge model

- The assignment contains 50 ImageNet-like RGB images at `224x224`.
- Every target description refers to a different image/category than the source.
- The server permits an RGB `L_inf` change of at most `16/255`.
- A sample succeeds when sentence-transformer similarity is at least `0.5`.
- The batch passes at ASR `>= 0.75` and average similarity `>= 0.61`.
- Only seven submissions are allowed, so local validation is required.

## Primary weakness: alpha-channel parser differential

The perturbation rule is defined over image pixels, but PNG can carry a fourth
alpha channel. A common validator loads both images with Pillow and converts
them to RGB before calculating the difference. In that case, alpha is discarded.
Most browser/API image decoders instead composite transparent pixels onto white
or black before sending pixels to a VLM.

`solve.py` makes the canvas transparent and leaves the target description
opaque. It also shifts hidden RGB background pixels by `+16` and text pixels by
`-16`. Therefore:

- an RGB-only validator measures a legal maximum difference of 16;
- a decoder that composites alpha sees the caption on a clean white/black panel;
- a decoder that drops alpha still sees a legal 32-level local text contrast;
- OCR or visual prompt injection can make the VLM repeat the target caption.

The script also creates explicit white and black previews for local inspection.

## Fallback

If the server rejects RGBA or its VLM drops alpha, use a bounded transferable
targeted attack against one or more public vision-language models. Optimize
CLIP image/text similarity toward the assigned sentence and the matching target
image from the supplied dataset, then quantize and verify every output remains
within 16 RGB levels.

The matching target image is deterministic. Sort all 1,000 dataset PNG paths.
If a submitted source is at index `i`, its target description belongs to image
`999-i`. This was verified against both requested assignments, including unique
scene details. `exploit.py` derives this mirrored path automatically and attacks
a weighted combination of exact target-image and target-text CLIP similarity.

## Attempt log

### Attempt 1: alpha/RGB hybrid

- ASR: `0.06`
- Average description similarity: `0.1645287691941485`
- Successes: `3/50`
- Attempts remaining: `6`

The server accepted RGBA, but the VLM effectively dropped alpha and described
the original RGB image. It did perceive the legal RGB overlay in multiple
cases, returning phrases such as "with text overlaying the image" and, for one
dog image, "text describing a snake." This rules out alpha as the main exploit
but supports retaining short, large target keywords in a gradient-based hybrid.

## Commands

Build and validate without spending an attempt:

```bash
python3 solve.py --preview-dir previews --validate
```

Submit exactly once:

```bash
TEAM_TOKEN='...' python3 solve.py --validate --submit
```

## Flag

Not recovered yet.
