"""
DES (Data Encryption Standard) - Pure Python Implementation from Scratch
========================================================================
1-2-1  Algorithm Overview
1-2-2  Component Details
1-2-3  Implementation Structure
1-2-4  Verification against known test vectors
1-2-5  Avalanche Effect, Completeness, Weak Key Analysis
"""

# ============================================================
# 1-2-2  DES Tables (all 1-indexed)
# ============================================================

# Initial Permutation (IP): 64-bit reorder at the start
IP = [
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7,
]

# Inverse Initial Permutation (IP⁻¹): undo IP after all rounds
IP_INV = [
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
]

# Permuted Choice 1 (PC-1): select 56 key bits, drop 8 parity bits
PC1 = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4,
]

# Permuted Choice 2 (PC-2): 56-bit half-key → 48-bit subkey
PC2 = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

# Expansion P-Box (E): 32-bit R → 48-bit (border bits replicated for diffusion)
E = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
]

# Straight P-Box (P): permute 32-bit S-box output for inter-round diffusion
P = [
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25,
]

# 8 S-Boxes: core non-linear component (48-bit → 32-bit, 6→4 bits each)
S_BOXES = [
    # S1
    [[14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7],
     [ 0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8],
     [ 4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0],
     [15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13]],
    # S2
    [[15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10],
     [ 3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5],
     [ 0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15],
     [13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9]],
    # S3
    [[10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1],
     [13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7],
     [ 1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12]],
    # S4
    [[ 7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15],
     [13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9],
     [10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4],
     [ 3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14]],
    # S5
    [[ 2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9],
     [14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6],
     [ 4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14],
     [11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3]],
    # S6
    [[12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11],
     [10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8],
     [ 9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6],
     [ 4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13]],
    # S7
    [[ 4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1],
     [13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6],
     [ 1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2],
     [ 6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12]],
    # S8
    [[13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7],
     [ 1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2],
     [ 7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8],
     [ 2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11]],
]

# Left-shift amounts per round (FIPS 46-3 §3.2)
SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


# ============================================================
# 1-2-3  Helper Functions
# ============================================================

def bytes_to_bits(data: bytes) -> list:
    """bytes → bit list, MSB first (bit 1 = MSB of byte 0)."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits: list) -> bytes:
    result = []
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)
    return bytes(result)


def permute(bits: list, table: list) -> list:
    """Apply permutation defined by 1-indexed table."""
    return [bits[i - 1] for i in table]


def xor_bits(a: list, b: list) -> list:
    return [x ^ y for x, y in zip(a, b)]


def left_rotate(bits: list, n: int) -> list:
    """Circular left shift."""
    return bits[n:] + bits[:n]


def bits_to_int(bits: list) -> int:
    result = 0
    for b in bits:
        result = (result << 1) | b
    return result


def int_to_bits(value: int, length: int) -> list:
    return [(value >> (length - 1 - i)) & 1 for i in range(length)]


def bits_to_hex(bits: list) -> str:
    return bits_to_bytes(bits).hex().upper()


def hamming_distance(a: bytes, b: bytes) -> int:
    """Count differing bits between two equal-length byte strings."""
    count = 0
    for x, y in zip(a, b):
        count += bin(x ^ y).count('1')
    return count


# ============================================================
# 1-2-2 / 1-2-3  Key Schedule
# ============================================================

def generate_subkeys(key: bytes) -> list:
    """
    64-bit key → sixteen 48-bit subkeys.

    PC-1 discards parity bits (pos 8,16,24,32,40,48,56,64) → 56 bits.
    Each round left-rotates C and D independently, then PC-2 selects 48 bits.
    Rotating C/D separately (not CD together) is the standard specification.
    """
    key_bits = bytes_to_bits(key)

    # PC-1: 64 → 56 bits (parity strips)
    key_56 = permute(key_bits, PC1)
    C, D = key_56[:28], key_56[28:]

    subkeys = []
    for rnd in range(16):
        C = left_rotate(C, SHIFT_SCHEDULE[rnd])
        D = left_rotate(D, SHIFT_SCHEDULE[rnd])
        subkeys.append(permute(C + D, PC2))   # PC-2: 56 → 48 bits

    return subkeys


# ============================================================
# 1-2-2 / 1-2-3  Feistel f-function
# ============================================================

def feistel(R: list, subkey: list) -> list:
    """
    f(R, K):
      1. Expansion E : 32 → 48 bits  (border-bit duplication for diffusion)
      2. XOR with 48-bit subkey
      3. 8 S-boxes    : 48 → 32 bits  (only non-linear step; provides confusion)
      4. Straight P   : 32 → 32 bits  (spread S-box output for next-round diffusion)
    """
    # Step 1 – Expansion
    R_exp = permute(R, E)          # 48 bits

    # Step 2 – XOR
    R_xor = xor_bits(R_exp, subkey)

    # Step 3 – S-Box substitution
    s_out = []
    for i in range(8):
        chunk = R_xor[i*6:(i+1)*6]        # 6 bits per S-box
        row = (chunk[0] << 1) | chunk[5]   # outer bits → row (0-3)
        col = bits_to_int(chunk[1:5])      # inner 4 bits → column (0-15)
        s_out.extend(int_to_bits(S_BOXES[i][row][col], 4))

    # Step 4 – Straight P
    return permute(s_out, P)


# ============================================================
# 1-2-3  DES Encrypt / Decrypt
# ============================================================

def des_encrypt(plaintext: bytes, key: bytes, verbose: bool = False) -> tuple:
    """
    Encrypt one 64-bit block.
    Returns (ciphertext, round_log).
    round_log keys: 'subkeys', 'rounds' (list of dicts with L, R, K per round).
    """
    assert len(plaintext) == 8 and len(key) == 8

    subkeys = generate_subkeys(key)
    pt_bits = bytes_to_bits(plaintext)

    # Initial Permutation
    perm = permute(pt_bits, IP)
    L, R = perm[:32], perm[32:]

    log = {'input': plaintext.hex().upper(),
           'key':   key.hex().upper(),
           'after_IP': bits_to_hex(perm),
           'subkeys': [bits_to_hex(sk) for sk in subkeys],
           'rounds': []}

    if verbose:
        print(f"\n{'─'*64}")
        print(f"Plaintext : {plaintext.hex().upper()}")
        print(f"Key       : {key.hex().upper()}")
        print(f"After IP  : {bits_to_hex(perm)}")
        print(f"L0={bits_to_hex(L)}  R0={bits_to_hex(R)}")
        print(f"{'─'*64}")
        print(f"{'Rnd':>3}  {'Subkey K':^12}  {'L (32-bit)':^10}  {'R (32-bit)':^10}")
        print(f"{'─'*64}")

    for rnd in range(16):
        L, R = R, xor_bits(L, feistel(R, subkeys[rnd]))
        log['rounds'].append({'round': rnd + 1,
                              'K':  bits_to_hex(subkeys[rnd]),
                              'L':  bits_to_hex(L),
                              'R':  bits_to_hex(R)})
        if verbose:
            print(f"{rnd+1:>3}  {bits_to_hex(subkeys[rnd])}  {bits_to_hex(L)}  {bits_to_hex(R)}")

    # Final swap then IP⁻¹
    ct_bits = permute(R + L, IP_INV)
    ciphertext = bits_to_bytes(ct_bits)
    log['ciphertext'] = ciphertext.hex().upper()

    if verbose:
        print(f"{'─'*64}")
        print(f"Ciphertext: {ciphertext.hex().upper()}")

    return ciphertext, log


def des_decrypt(ciphertext: bytes, key: bytes, verbose: bool = False) -> bytes:
    """Decrypt one 64-bit block (same circuit, subkeys reversed)."""
    assert len(ciphertext) == 8 and len(key) == 8

    subkeys = generate_subkeys(key)[::-1]   # reverse for decryption
    ct_bits = bytes_to_bits(ciphertext)

    perm = permute(ct_bits, IP)
    L, R = perm[:32], perm[32:]

    if verbose:
        print(f"\n{'─'*64}  [DECRYPT]")
        print(f"Ciphertext: {ciphertext.hex().upper()}")
        print(f"{'─'*64}")

    for rnd in range(16):
        L, R = R, xor_bits(L, feistel(R, subkeys[rnd]))
        if verbose:
            print(f"Rnd {rnd+1:2d}: L={bits_to_hex(L)} R={bits_to_hex(R)}")

    pt_bits = permute(R + L, IP_INV)
    return bits_to_bytes(pt_bits)


# ============================================================
# 1-2-4  Known Test Vector Verification
# ============================================================

# Vectors from FIPS 46-3 / Stallings "Cryptography and Network Security"
# and NIST SP 500-20 Variable-Plaintext KAT (KEY=0101010101010101)
# and Variable-Key KAT (PT=0000000000000000).
KNOWN_VECTORS = [
    # name, plaintext_hex, key_hex, ciphertext_hex
    ("Stallings classic",
     "0123456789ABCDEF", "133457799BBCDFF1", "85E813540F0AB405"),
    # NIST SP 500-20 Variable-Plaintext KAT (key = 0101… = all data bits 0)
    ("NIST Var-PT #1  PT=8000…, Key=0101…",
     "8000000000000000", "0101010101010101", "95F8A5E5DD31D900"),
    ("NIST Var-PT #2  PT=4000…, Key=0101…",
     "4000000000000000", "0101010101010101", "DD7F121CA5015619"),
    ("NIST Var-PT #3  PT=2000…, Key=0101…",
     "2000000000000000", "0101010101010101", "2E8653104F3834EA"),
    # NIST SP 500-20 Variable-Key KAT (PT = 0000…)
    ("NIST Var-Key #1 PT=0000…, Key=8001…",
     "0000000000000000", "8001010101010101", "95A8D72813DAA94D"),
    ("NIST Var-Key #2 PT=0000…, Key=4001…",
     "0000000000000000", "4001010101010101", "0EEC1487DD8C26D5"),
]


def verify_vectors(verbose: bool = True) -> bool:
    print("\n" + "═"*64)
    print("  1-2-4  KNOWN TEST VECTOR VERIFICATION")
    print("═"*64)

    all_ok = True
    for name, pt_hex, k_hex, ct_hex in KNOWN_VECTORS:
        pt  = bytes.fromhex(pt_hex)
        key = bytes.fromhex(k_hex)
        expected = bytes.fromhex(ct_hex)

        got, _ = des_encrypt(pt, key)
        decrypted = des_decrypt(got, key)

        enc_ok = (got == expected)
        dec_ok = (decrypted == pt)
        status = "PASS" if enc_ok else "FAIL"
        all_ok = all_ok and enc_ok

        if verbose:
            print(f"\n  [{status}] {name}")
            print(f"    PT  : {pt_hex}")
            print(f"    Key : {k_hex}")
            print(f"    Exp : {ct_hex}")
            print(f"    Got : {got.hex().upper()}")
            print(f"    Dec : {decrypted.hex().upper()}  (matches PT: {dec_ok})")

    print(f"\n  Result: {'ALL PASS ✓' if all_ok else 'FAILURES DETECTED ✗'}")
    return all_ok


# ============================================================
# 1-2-4  Round-by-round verbose demo
# ============================================================

def verbose_demo():
    print("\n" + "═"*64)
    print("  1-2-4  ROUND-BY-ROUND ENCRYPTION (Stallings example)")
    print("═"*64)
    pt  = bytes.fromhex("0123456789ABCDEF")
    key = bytes.fromhex("133457799BBCDFF1")
    ct, log = des_encrypt(pt, key, verbose=True)

    print(f"\n  Subkeys K1–K16:")
    for i, sk in enumerate(log['subkeys']):
        print(f"    K{i+1:2d}: {sk}")

    print(f"\n  Decryption check:")
    dec = des_decrypt(ct, key, verbose=False)
    print(f"    Ciphertext : {ct.hex().upper()}")
    print(f"    Decrypted  : {dec.hex().upper()}")
    print(f"    Match PT   : {dec == pt}")


# ============================================================
# 1-2-5  Avalanche Effect
# ============================================================

def avalanche_plaintext(pt: bytes, key: bytes) -> list:
    """
    Flip each of the 64 plaintext bits one at a time.
    Return list of Hamming distances from the original ciphertext.
    """
    orig_ct, _ = des_encrypt(pt, key)
    diffs = []
    for pos in range(64):
        bits = bytes_to_bits(pt)
        bits[pos] ^= 1
        ct, _ = des_encrypt(bits_to_bytes(bits), key)
        diffs.append(hamming_distance(orig_ct, ct))
    return diffs


def avalanche_key(pt: bytes, key: bytes) -> list:
    """Flip each of the 64 key bits; measure ciphertext bit change."""
    orig_ct, _ = des_encrypt(pt, key)
    diffs = []
    for pos in range(64):
        bits = bytes_to_bits(key)
        bits[pos] ^= 1
        ct, _ = des_encrypt(pt, bits_to_bytes(bits))
        diffs.append(hamming_distance(orig_ct, ct))
    return diffs


def print_avalanche(title: str, diffs: list):
    avg = sum(diffs) / len(diffs)
    print(f"\n  {title}")
    print(f"  {'─'*50}")
    print(f"  Tests     : {len(diffs)} (one bit flip per test)")
    print(f"  Avg Δ bits: {avg:.2f} / 64  ({avg/64*100:.1f}%)")
    print(f"  Min / Max : {min(diffs)} / {max(diffs)}")
    print(f"  Ideal     : ~32 bits (50%)")
    print(f"\n  First 16 results:")
    for i in range(0, 16, 4):
        row = diffs[i:i+4]
        labels = [f"bit{i+j:02d}→{d:2d}b" for j, d in enumerate(row)]
        print(f"    {'   '.join(labels)}")


def run_avalanche_analysis(pt: bytes, key: bytes):
    print("\n" + "═"*64)
    print("  1-2-5  AVALANCHE EFFECT ANALYSIS")
    print("═"*64)
    print(f"  Plaintext : {pt.hex().upper()}")
    print(f"  Key       : {key.hex().upper()}")

    pt_diffs  = avalanche_plaintext(pt, key)
    key_diffs = avalanche_key(pt, key)

    print_avalanche("A. Plaintext bit-flip  → ciphertext change", pt_diffs)
    print_avalanche("B. Key bit-flip        → ciphertext change", key_diffs)

    return pt_diffs, key_diffs


# ============================================================
# 1-2-5  Completeness Effect
# ============================================================

def run_completeness_analysis(pt: bytes, key: bytes):
    """
    For each output bit o, count how many of the 64 input bits affect it.
    A fully complete cipher has every output bit affected by all input bits.
    """
    print("\n" + "═"*64)
    print("  1-2-5  COMPLETENESS EFFECT ANALYSIS")
    print("═"*64)

    orig_ct, _ = des_encrypt(pt, key)
    orig_bits  = bytes_to_bits(orig_ct)

    # dependency[o] = number of input bits that change output bit o
    dependency = [0] * 64

    for pos in range(64):
        bits = bytes_to_bits(pt)
        bits[pos] ^= 1
        mod_ct, _ = des_encrypt(bits_to_bytes(bits), key)
        mod_bits = bytes_to_bits(mod_ct)
        for o in range(64):
            if orig_bits[o] != mod_bits[o]:
                dependency[o] += 1

    avg = sum(dependency) / 64
    full = sum(1 for d in dependency if d == 64)

    print(f"  Avg input bits affecting each output bit : {avg:.1f} / 64  ({avg/64*100:.1f}%)")
    print(f"  Output bits influenced by ALL 64 inputs  : {full}")
    print(f"  Min / Max dependency                     : {min(dependency)} / {max(dependency)}")

    print(f"\n  Dependency per output bit (groups of 8):")
    for i in range(0, 64, 8):
        vals = dependency[i:i+8]
        print(f"    Out {i:2d}-{i+7:2d}: {vals}")

    return dependency


# ============================================================
# 1-2-5  Weak Key & Semi-Weak Key Analysis
# ============================================================

# 4 DES weak keys: all subkeys are identical → double encryption = identity
WEAK_KEYS = {
    "WK-1 (all 0 in 56-bit key)":    bytes.fromhex("0101010101010101"),
    "WK-2 (all 1 in 56-bit key)":    bytes.fromhex("FEFEFEFEFEFEFEFE"),
    "WK-3 (0xE0… / 0xF1…)":          bytes.fromhex("E0E0E0E0F1F1F1F1"),
    "WK-4 (0x1F… / 0x0E…)":          bytes.fromhex("1F1F1F1F0E0E0E0E"),
}

# 6 semi-weak key pairs: E(P, K1) = D(P, K2)  ↔  D(E(P,K1), K2) = P
SEMI_WEAK_PAIRS = [
    (bytes.fromhex("01FE01FE01FE01FE"), bytes.fromhex("FE01FE01FE01FE01")),
    (bytes.fromhex("1FE01FE00EF10EF1"), bytes.fromhex("E01FE01FF10EF10E")),
    (bytes.fromhex("01E001E001F101F1"), bytes.fromhex("E001E001F101F101")),
    (bytes.fromhex("1FFE1FFE0EFE0EFE"), bytes.fromhex("FE1FFE1FFE0EFE0E")),
    (bytes.fromhex("011F011F010E010E"), bytes.fromhex("1F011F010E010E01")),
    (bytes.fromhex("E0FEE0FEF1FEF1FE"), bytes.fromhex("FEE0FEE0FEF1FEF1")),
]


def run_weak_key_analysis(pt: bytes):
    print("\n" + "═"*64)
    print("  1-2-5  WEAK KEY & SEMI-WEAK KEY ANALYSIS")
    print("═"*64)
    print(f"  Plaintext: {pt.hex().upper()}")

    # ── Weak Keys ──────────────────────────────────────────
    print("\n  [A] Weak Keys — E(E(P, K), K) = P  (double-encrypt = identity)")
    print(f"  {'─'*60}")
    for name, wk in WEAK_KEYS.items():
        subkeys = generate_subkeys(wk)
        unique_sk = len(set(tuple(s) for s in subkeys))

        ct, _        = des_encrypt(pt, wk)
        double_ct, _ = des_encrypt(ct, wk)
        is_identity  = (double_ct == pt)

        print(f"\n  {name}")
        print(f"    Key              : {wk.hex().upper()}")
        print(f"    Unique subkeys   : {unique_sk}  (weak key → all 16 identical)")
        print(f"    E(P, K)          : {ct.hex().upper()}")
        print(f"    E(E(P,K), K)     : {double_ct.hex().upper()}")
        print(f"    Equals P?        : {is_identity}  ← {'⚠ VULNERABLE' if is_identity else 'OK'}")

    # ── Semi-Weak Key Pairs ────────────────────────────────
    # Property: E_K1 = D_K2, which means E(E(P,K1), K2) = P
    # (subkeys of K2 in reverse equal subkeys of K1 forward)
    print("\n\n  [B] Semi-Weak Pairs — E(E(P, K1), K2) = P")
    print(f"  {'─'*60}")
    for i, (k1, k2) in enumerate(SEMI_WEAK_PAIRS, 1):
        ct_k1, _ = des_encrypt(pt, k1)
        ct_k1_k2, _ = des_encrypt(ct_k1, k2)   # should recover P
        is_semi = (ct_k1_k2 == pt)

        # Also verify symmetric direction: E(E(P,K2),K1) = P
        ct_k2, _ = des_encrypt(pt, k2)
        ct_k2_k1, _ = des_encrypt(ct_k2, k1)
        is_sym = (ct_k2_k1 == pt)

        print(f"\n  Pair {i}:")
        print(f"    K1                    : {k1.hex().upper()}")
        print(f"    K2                    : {k2.hex().upper()}")
        print(f"    E(P, K1)              : {ct_k1.hex().upper()}")
        print(f"    E(E(P,K1), K2)        : {ct_k1_k2.hex().upper()}")
        print(f"    Equals P?  (K1→K2)   : {is_semi}  ← {'⚠ VULNERABLE' if is_semi else 'OK'}")
        print(f"    Equals P?  (K2→K1)   : {is_sym}   ← {'⚠ VULNERABLE' if is_sym else 'OK'}")


# ============================================================
# Main
# ============================================================

def main():
    print("═"*64)
    print("  DES — Pure Python Implementation  (FIPS 46-3)")
    print("  Sections: 1-2-1 ~ 1-2-5")
    print("═"*64)

    # ── 1-2-1  Algorithm overview printed inline above each section ──

    # ── 1-2-4  Verbose round-by-round demo ──────────────────
    verbose_demo()

    # ── 1-2-4  Known vector verification ────────────────────
    verify_vectors()

    # ── 1-2-5  Avalanche ────────────────────────────────────
    pt  = bytes.fromhex("0123456789ABCDEF")
    key = bytes.fromhex("133457799BBCDFF1")
    run_avalanche_analysis(pt, key)

    # ── 1-2-5  Completeness ──────────────────────────────────
    run_completeness_analysis(pt, key)

    # ── 1-2-5  Weak keys ────────────────────────────────────
    run_weak_key_analysis(pt)


if __name__ == "__main__":
    main()
