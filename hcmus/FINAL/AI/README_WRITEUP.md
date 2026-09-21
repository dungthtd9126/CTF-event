# Decent Normally Bedbug — solve write-up

## Category

Computer vision / adversarial ML. The server is not meant to be brute-forced: it allows only 7 submissions, gives a random image batch, checks that each submitted image is within a small L∞ pixel-difference budget, then scores the VLM output against the target description using `sentence-transformers/stsb-distilroberta-base-v2`.

## Key observation

The perturbation limit is:

```text
max diff <= 0.062745098 = 16 / 255
```

That is small per pixel, but it is not a small **global** change. We can change every pixel by up to 16 RGB levels. This is enough to render faint but machine-readable text. Modern VLMs/OCR pipelines strongly attend to text in images, so we can place the target prompt itself into the image as repeated low-contrast text.

To maximize OCR readability while respecting the bound, the solver draws a dark low-contrast rectangle and bright low-contrast text on top:

```text
background box: original - 16
text pixels:    original + 16
```

The local edge contrast is therefore up to `32/255`, while every individual pixel still remains inside the server's `16/255` L∞ limit.

The submitted ZIP keeps the exact expected entry names from `/assignment`, but encodes each image losslessly as PNG bytes. This avoids JPEG recompression artifacts, which can easily violate the diff bound.

## Usage

Install dependencies:

```bash
python3 -m pip install pillow numpy requests py7zr
```

Run a safe dry run first. This requests/loads an assignment, downloads/extracts the dataset if needed, builds `submission.zip`, and does **not** spend a submission:

```bash
python3 decent_solver.py --status --new-assignment
```

Submit once when ready:

```bash
python3 decent_solver.py --submit
```

If the Google Drive download fails locally, download `Data.7z` from the challenge link manually and run:

```bash
python3 decent_solver.py --data-archive ./Data.7z --new-assignment
python3 decent_solver.py --data-archive ./Data.7z --submit
```

If the first submission unexpectedly misses the ASR/average-similarity thresholds, try one stronger layout. Each `--submit` costs one attempt, so do not run all variants blindly:

```bash
python3 decent_solver.py --variant tile --submit
```

## Why this passes

The challenge success metric is semantic similarity between the model response and the target prompt. By embedding the exact target prompt in the image, the VLM tends to mention the text it sees. Even when it answers in the form “the image contains text saying ...”, the response still contains the target phrase, which is enough for the STS similarity threshold.

The attack is deterministic and does not require gradient access, model extraction, or repeated probing.

## Solver summary

1. Call `/status` to check attempts.
2. Call `/assignment` once to receive `assignment_id`, exact expected ZIP names, and per-image target prompts.
3. Locate each original image in the extracted dataset.
4. Render the target text as bounded OCR-style perturbation.
5. Assert `max(abs(adversarial - original)) <= 16` locally.
6. Write a ZIP whose entries match `expected_images` exactly.
7. Submit the ZIP to `/submit?assignment_id=...`.

## Notes

The included script defaults to the challenge token and server from the provided client. You can override them with environment variables:

```bash
export CHALLENGE_URL='https://decent-normally-bedbug.ngrok-free.app/'
export TEAM_TOKEN='ctf_token_team1_xyz'
python3 decent_solver.py --new-assignment --submit
```
