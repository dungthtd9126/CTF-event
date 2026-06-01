# crypto/Funny Helicopter Morphology - 2 Write-up

## Challenge summary

The challenge service is a crypto server with three useful commands:

- `PARAMS`: prints the main BFV parameters and an encrypted flag.
- `EVALSUM`: prints the auxiliary samples `B0, S0, B1, S1`, but using it before `PARAMS` changes the encrypted flag to flag 1.
- `CHALLENGE`: returns chosen-plaintext BFV-like samples under the hidden main secret `S` and also leaks two error coefficients `E[0]` and `E[1]`.

The important detail for flag 2 is this branch in `server_new.cpp`:

```cpp
if (action == "PARAMS") {
    ...
    "Encrypted flag: " + (used_hint ? encrypted_flag_1 : encrypted_flag_2) + "\n";
    used_params = true;
}
else if (action == "EVALSUM") {
    if (used_params) {
        continue;
    }
    used_hint = true;
    ...
}
```

So if we call `EVALSUM` first, `used_hint` becomes true and `PARAMS` gives flag 1. For flag 2, we must call `PARAMS` first, then avoid relying on `EVALSUM`.

The final working command was:

```bash
python3 solve_fhm2.py chall.blackpinker.com 20941 --instances 6 --max-k 8 --keep 100000 --pair-bound 200
```

## Vulnerability / weakness

The server generates an auxiliary secret polynomial `T` with 8 sorted coefficients in this interval:

```cpp
T_MIN = 2^59
T_MAX = 2^60
```

Then it generates two auxiliary RLWE-like samples:

```text
S0 = B0*T + K0 mod q_aux
S1 = B1*T + K1 mod q_aux
```

where:

- `B0` and `B1` are ternary polynomials, so each coefficient is in `{-1, 0, 1}`.
- `K0` and `K1` are tiny Gaussian error polynomials, with sigma about `2.0`.
- `S0 || S1` is copied into the main 16-coefficient secret `S`.

The encrypted flag is not a real BFV encryption. It is simply XORed with bytes derived from the signed coefficients of `T`:

```cpp
const std::vector<int64_t> t_coeffs = GetPolyCoefficientsSigned(T);
for (int64_t coeff : t_coeffs) {
    for (int j = 0; j < 8; j++) {
        key_bytes.push_back((coeff >> (j * 8)) & 0xff);
    }
}
masked_body[i] = flag_body[i] ^ key_bytes[i % key_bytes.size()];
```

Therefore, recovering `T` is enough to decrypt the flag.

## Step 1: Get flag 2 ciphertext

The solver opens a new connection and sends `PARAMS` immediately:

```text
PARAMS
```

This returns:

```text
n: 16
q: ...
q0: ...
Encrypted flag: ...
```

Because `PARAMS` is sent before `EVALSUM`, this ciphertext is `encrypted_flag_2`.

## Step 2: Recover the copied main secret `S`

After `PARAMS`, the solver sends a zero plaintext challenge:

```text
CHALLENGE 10 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
```

The service returns 10 samples:

```text
r: <random r>
SAMPLE i
C1: [...]
C0: [...]
```

From the source code, each sample is generated as:

```cpp
c0 = a * S + e * r + m_poly;
```

We choose `m_poly = 0`, so:

```text
C0 = C1*S + r*e mod q
```

Reducing modulo `r` removes the noise term:

```text
C0 = C1*S mod r
```

This is a linear system over `Z/rZ` for the 16 coefficients of `S`. Because we request 10 samples and each sample gives 16 coefficient equations, we get about 160 equations for only 16 unknowns.

The solver builds the negacyclic multiplication matrix for each `C1`, solves the linear system modulo `r`, and obtains `S mod r`.

The true coefficients of `S` are first-tower residues coming from the auxiliary samples. They are close to `q0` and below about `2^60`, while `r` is randomly chosen below `q0`. If `r` is large enough, each residue has only a small number of possible integer lifts:

```text
S_i = s_i_mod_r + h_i*r
```

The solver tries the few possible lifts and chooses the one where:

```text
(C0 - C1*S) / r
```

has tiny Gaussian coefficients. This gives the full 16-coefficient secret:

```text
S = S0 || S1
```

where `S0` and `S1` are the two hidden auxiliary samples.

## Step 3: Find the auxiliary modulus `q_aux`

The auxiliary BFV context uses ring dimension 8. Its first CRT modulus is a 60-bit NTT prime. The solver tries likely OpenFHE primes near the printed `q0`, and can also scan nearby primes congruent to `1 mod 16`.

In practice the correct `q_aux` appears among the small candidate list. If needed, `--scan-qaux` can be increased.

## Step 4: Recover `B0` and `B1` with meet-in-the-middle

We now know:

```text
S0 = B0*T + K0 mod q_aux
S1 = B1*T + K1 mod q_aux
```

The unknowns are `B0`, `B1`, `T`, `K0`, and `K1`.

The key trick is to eliminate `T`. Multiplication in the negacyclic polynomial ring is commutative, so:

```text
B1*S0 - B0*S1
= B1*(B0*T + K0) - B0*(B1*T + K1)
= B1*K0 - B0*K1
```

The right-hand side is small because `B0`, `B1`, `K0`, and `K1` are all small.

There are only `3^8 - 1 = 6560` non-zero ternary polynomials of degree 8. A direct pair search over all `(B0, B1)` is possible but slower. The solver uses meet-in-the-middle:

1. Enumerate all ternary `B0` and store `B0*S1`.
2. Enumerate all ternary `B1` and compute `B1*S0`.
3. Keep pairs where `B1*S0 - B0*S1` is small modulo `q_aux`.

The `--pair-bound 200` option allows this small-difference check to tolerate the Gaussian errors. Your successful run used:

```text
--pair-bound 200
```

which is wider than the default and handles unlucky instances better.

## Step 5: Recover `T` using leaked `K0[0]` and `K0[1]`

The `CHALLENGE` response leaks two auxiliary error coefficients:

```cpp
for (size_t i = 0; i < std::min<size_t>(2, e_coeffs.size()); i++) {
    ss_res << "E[" << i << "]: " << e_coeffs[i] << "\n";
}
```

These are `K0[0]` and `K0[1]`.

For each candidate `(B0, B1)`, if `B0` is invertible modulo `q_aux`, then:

```text
T = B0^{-1} * (S0 - K0) mod q_aux
```

Only six coefficients of `K0` are still unknown. Since the Gaussian sigma is only `2.0`, they are very small. The solver searches them in the range:

```text
[-K, K]
```

Your successful run used:

```text
--max-k 8
```

meaning the solver tried error bounds up to `K = 8`.

To avoid a huge brute force over `(2K+1)^6`, the solver splits the six unknown error coefficients into `3 + 3` and uses another meet-in-the-middle. For each possible `K0`, the solver computes candidate `T`, then validates:

- every coefficient of `T` lifts into `[2^59, 2^60)`,
- the coefficients of `T` are sorted, matching `GenLargeSecretPoly()`,
- the derived `K1 = S1 - B1*T` is also small.

This leaves a manageable number of possible `T` values per instance.

## Step 6: Decrypt candidate flag bodies

For each valid `T`, the solver recreates the XOR key exactly like the server.

Because `T_i` is in `[2^59, 2^60)` and the first auxiliary prime is slightly above that range, `GetPolyCoefficientsSigned(T)` returns:

```text
signed_T_i = T_i - q_aux
```

Then the solver converts each signed 64-bit coefficient into little-endian bytes and XORs the encrypted flag body.

The solver keeps plaintexts that use a reasonable flag charset.

## Step 7: Use multiple connections to remove random hex padding

The flag body is padded to at least 32 bytes:

```cpp
size_t target_len = max(32, body.length());
if (flag_body.length() < target_len) {
    flag_body += random_hex_padding;
}
```

So the decrypted body may look like:

```text
real_flag_body<random hex suffix>
```

The real flag body is constant, but the hex padding changes every connection. Therefore the solver collects several independent instances and intersects plaintext candidates by common prefix.

Your successful command used:

```text
--instances 6
--keep 100000
```

This gives enough independent decrypted candidate sets and keeps enough low-noise candidates so that the real common prefix survives the pruning.

At the end, the solver prints:

```text
[+] raw body: ...
[+] stripped body: ...
HCMUS-CTF{...}
```

The `stripped body` line removes the random trailing hex padding, following the challenge note: “remove hex characters at the end”.

## Why the final command works

```bash
python3 solve_fhm2.py chall.blackpinker.com 20941 --instances 6 --max-k 8 --keep 100000 --pair-bound 200
```

Meaning of the important options:

- `--instances 6`: collect six independent server instances, making the common-prefix check reliable.
- `--max-k 8`: allow Gaussian error coefficients up to absolute value 8.
- `--keep 100000`: keep many plaintext candidates per instance so the correct one is not pruned.
- `--pair-bound 200`: allow a wider smallness bound when searching for `(B0, B1)` pairs.

The attack does not need `EVALSUM`, so it does not accidentally switch the target to flag 1. It recovers the hidden auxiliary secret `T` indirectly through the chosen-plaintext `CHALLENGE` equations, then decrypts flag 2.

## Reproducibility

Run:

```bash
python3 solve_fhm2.py chall.blackpinker.com 20941 --instances 6 --max-k 8 --keep 100000 --pair-bound 200
```

Submit the final line printed by the solver:

```text
HCMUS-CTF{<stripped_body>}
```

If the solver prints both `raw body` and `stripped body`, submit the `stripped body` version because the random trailing hex is not part of the flag.
