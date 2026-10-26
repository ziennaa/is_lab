"""
IS LAB ENDSEM OPEN-BOOK TOOLKIT — LABS 1 TO 8
================================================
Purpose:
1. Keep reusable functions for major patterns from Labs 1–8.
2. Each executable line has a short comment so you can understand/edit it during the exam.
3. Search QUESTION SAYS below or a q_ function and copy its helper functions.
4. Grant and voting role menus are self-contained here and save records after restart.

IMPORTANT:
- Classical-cipher code is for lab learning, not real-world security.
- Modern crypto sections use PyCryptodome. Install with: pip install pycryptodome


python -m pip install pycryptodome cryptography matplotlib
from Crypto.Cipher import AES
from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from Crypto.Util.number import getPrime
from cryptography.hazmat.primitives.asymmetric import ec

print("All libraries available!")
print("Everything working!")





AES KEY

Use it whenever the question says generate a random AES key.
key128 = get_random_bytes(16) 128
key192 = get_random_bytes(24) 192
key256 = get_random_bytes(32) 256

What if the question gives a fixed hexadecimal key?
key = aes_key_from_hex(hex_key)

HELLO = bytes  use encode
bytes = normal - use decode
bytes - hex string using .hex

# ONCE before the menu
index_key = get_random_bytes(32)

# WHILE STORING
idtoken = search_token(id, index_key)
records.append({"tokens": [idtoken], ...})

# WHILE SEARCHING
found = searchable_find(records, val, index_key)

if found:
    record = found[0]


tampering

r = records[0]
tampered = bytearray(r["encrypted_data"])
tampered[0] ^= 1
"""

# ============================================================================
# QUESTION SAYS → SEARCH THESE FUNCTION NAMES WITH CTRL+F
# ============================================================================
# QUESTION SAYS: AES-192 grant description → grant_submit / aes_cbc_pack.
# QUESTION SAYS: Paillier amount / encrypted sum → paillier_encrypt / paillier_add / grant_aggregate.
# QUESTION SAYS: MD5 and RSA sign the record → rsa_sign_md5 / rsa_verify_md5 / grant_verify.
# QUESTION SAYS: searchable Grant ID / review / hex dump → grant_search / q_grant_reviewer_verify_search_hex.
# QUESTION SAYS: menu-driven researcher/reviewer/finance → grant_menu (complete runnable program).
# QUESTION SAYS: SHA-512 ballot, AES-256-CBC, RSA-4096 wrapped key → vote_cast / vote_verify.
# QUESTION SAYS: ElGamal signature, timestamp, constituency index → vote_cast / vote_verify / vote_search.
# QUESTION SAYS: homomorphic candidate tally / threshold demo → vote_tally / recover_private_for_final.
# QUESTION SAYS: menu-driven voter/server/commission → vote_menu (complete runnable program).
# QUESTION SAYS: Paillier 15+25 → q_lab7_paillier_add_15_and_25.
# QUESTION SAYS: RSA textbook 7*3 or ElGamal product → q_lab7_rsa_multiply_7_and_3 / q_lab7_elgamal_homomorphic_multiplication.
# QUESTION SAYS: ten-document AES searchable index → q_lab8_sse_aes_ten_documents_search.
# QUESTION SAYS: Paillier encrypted document IDs → q_lab8_paillier_encrypted_document_ids (see limitations).
# QUESTION SAYS: any new scenario / roles / persistence → load_json / save_json / choose_menu.
# LAB 1: additive / affine / Vigenere / autokey / Playfair / Hill → search *_encrypt or lab1_q.
# LAB 2: AES / DES / 3DES / modes / timing → search aes_cbc_encrypt, des_encrypt, time_aes_modes.
# LAB 3: RSA / ElGamal / ECC / DH → search rsa_hybrid_encrypt, elgamal_encrypt_int, dh_demo.
# LAB 4: Rabin / RBAC / key management → search rabin_decrypt_roots, rbac_allowed, RabinKeyManager.
# LAB 5: hashing / tamper / sockets → search md5_hex, integrity_check, hash_server.
# LAB 6: signatures / Schnorr → search rsa_sign_sha256, elgamal_sign, schnorr_sign.
# LAB 7: Paillier / homomorphic → search paillier_encrypt, paillier_add, q_lab7_ functions.
# LAB 8: SSE / encrypted index → search sse_build_inverted, searchable_find, q_lab8_ functions.
# Run: python IS_Exam_Toolkit_Labs_1_to_8.py [find | grant | vote].
# For find, paste a full question then type END on its own line.

# =========================
# COMMON IMPORTS
# =========================
import math  # Gives gcd() and other basic math functions.
import time  # Used to measure encryption/decryption or hashing time.
import random  # Used to generate random values for ElGamal/DH and datasets.
import string  # Gives letters/digits for random test strings.
import hashlib  # Gives MD5, SHA-1 and SHA-256 hashing.
import socket  # Used for client-server lab questions.
from datetime import datetime  # Used to generate timestamps.
from pathlib import Path  # Makes file handling simple and readable.

from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP  # Modern symmetric ciphers and RSA-OAEP.
from Crypto.PublicKey import RSA  # Generates and loads RSA public/private keys.
from Crypto.Signature import pkcs1_15  # Creates and verifies RSA digital signatures.
from Crypto.Hash import SHA256  # SHA-256 object compatible with RSA signing.
from Crypto.Random import get_random_bytes  # Secure random bytes for keys/IVs/nonces.
from Crypto.Util.Padding import pad, unpad  # Adds/removes block padding for AES/DES.
from Crypto.Util.number import inverse  # Finds modular inverse for ElGamal/Rabin helpers.


# ============================================================
# LAB 1 — BASIC SYMMETRIC / CLASSICAL CIPHERS
# Manual patterns: Additive, Multiplicative, Affine, Vigenere,
# Autokey, Playfair, Hill, brute-force/known-plaintext attacks.
# ============================================================
import json

def to_string(data):
    if isinstance(data, str):
        return data
    elif isinstance(data, tuple):
        return json.dumps(list(data))
    else:
        return json.dumps(data)

'''import json

def to_string(data):
    if isinstance(data, str):
        return data
    elif isinstance(data, tuple):
        return json.dumps(list(data))
    else:
        return json.dumps(data)


if ch == "1":
    students = [
        ("s1", "alice", 90, "pass"),
        ("s2", "bob", 56, "pass"),
        ("s3", "eve", 45, "fail")
    ]

    for sid, sname, marks, status in students:

        # Convert only name, marks and status to string
        data = to_string((sname, marks, status))

        enc, iv = aes_cbc_encrypt(data, aes_key)
        shahash = sha256_hex(enc)
        signature = rsa_sign_sha256(enc, private)

        records.append({
            "id": sid,
            "encrypted": enc,
            "iv": iv,
            "hash": shahash,
            "sign": signature
        })

    print("3 student records created!")


plain = aes_cbc_decrypt(
    found["encrypted"], aes_key, found["iv"]
).decode()

sname, marks, status = json.loads(plain)

print("Name:", sname)
print("Marks:", marks)
print("Status:", status)
'''
def clean_letters(text):  # Remove spaces/punctuation and convert to lowercase.
    return "".join(ch.lower() for ch in text if ch.isalpha())  # Keep only alphabetic characters.


def additive_encrypt(text, key):  # Caesar/additive encryption: C = (P + key) mod 26.
    text = clean_letters(text)  # Normalize the input first.
    result = ""  # Store the ciphertext here.
    for ch in text:  # Process one character at a time.
        p = ord(ch) - ord("a")  # Convert a-z to 0-25.
        c = (p + key) % 26  # Apply the additive-cipher formula.
        result += chr(c + ord("a"))  # Convert 0-25 back to a letter.
    return result  # Return the completed ciphertext.


def additive_decrypt(ciphertext, key):  # Caesar/additive decryption: P = (C - key) mod 26.
    result = ""  # Store the plaintext here.
    for ch in ciphertext.lower():  # Process each ciphertext letter.
        c = ord(ch) - ord("a")  # Convert the letter to 0-25.
        p = (c - key) % 26  # Reverse the shift.
        result += chr(p + ord("a"))  # Convert number back to a letter.
    return result  # Return the recovered plaintext.


def multiplicative_encrypt(text, key):  # Multiplicative encryption: C = P*key mod 26.
    if math.gcd(key, 26) != 1:  # Check whether the key has a multiplicative inverse.
        raise ValueError("Multiplicative key must be coprime with 26.")  # Reject invalid key.
    text = clean_letters(text)  # Normalize the plaintext.
    result = ""  # Store ciphertext here.
    for ch in text:  # Process each letter.
        p = ord(ch) - ord("a")  # Convert letter to 0-25.
        c = (p * key) % 26  # Multiply by the key modulo 26.
        result += chr(c + ord("a"))  # Convert number back to a letter.
    return result  # Return ciphertext.


def multiplicative_decrypt(ciphertext, key):  # Reverse the multiplicative cipher.
    key_inv = pow(key, -1, 26)  # Find key inverse modulo 26.
    result = ""  # Store recovered plaintext.
    for ch in ciphertext.lower():  # Process each encrypted letter.
        c = ord(ch) - ord("a")  # Convert letter to 0-25.
        p = (c * key_inv) % 26  # Multiply by inverse key.
        result += chr(p + ord("a"))  # Convert number to a letter.
    return result  # Return plaintext.


def affine_encrypt(text, a, b):  # Affine encryption: C = (aP + b) mod 26.
    if math.gcd(a, 26) != 1:  # Ensure 'a' is invertible modulo 26.
        raise ValueError("Affine key 'a' must be coprime with 26.")  # Stop for invalid a.
    text = clean_letters(text)  # Normalize plaintext.
    result = ""  # Store ciphertext.
    for ch in text:  # Process each letter.
        p = ord(ch) - ord("a")  # Convert letter to 0-25.
        c = (a * p + b) % 26  # Apply affine formula.
        result += chr(c + ord("a"))  # Convert number back to letter.
    return result  # Return ciphertext.


def affine_decrypt(ciphertext, a, b):  # Affine decryption: P = a^-1(C-b) mod 26.
    a_inv = pow(a, -1, 26)  # Compute inverse of a modulo 26.
    result = ""  # Store plaintext.
    for ch in ciphertext.lower():  # Process each encrypted letter.
        c = ord(ch) - ord("a")  # Convert letter to 0-25.
        p = (a_inv * (c - b)) % 26  # Reverse affine transformation.
        result += chr(p + ord("a"))  # Convert number back to letter.
    return result  # Return plaintext.


def vigenere_encrypt(text, key):  # Vigenere encryption with a repeating keyword.
    text = clean_letters(text)  # Normalize plaintext.
    key = clean_letters(key)  # Normalize key.
    result = ""  # Store ciphertext.
    for i, ch in enumerate(text):  # Track both position and character.
        p = ord(ch) - ord("a")  # Convert plaintext letter to 0-25.
        k = ord(key[i % len(key)]) - ord("a")  # Reuse keyword cyclically.
        result += chr(((p + k) % 26) + ord("a"))  # Shift by current key letter.
    return result  # Return ciphertext.


def vigenere_decrypt(ciphertext, key):  # Reverse Vigenere encryption.
    ciphertext = clean_letters(ciphertext)  # Normalize ciphertext.
    key = clean_letters(key)  # Normalize key.
    result = ""  # Store plaintext.
    for i, ch in enumerate(ciphertext):  # Process each encrypted letter.
        c = ord(ch) - ord("a")  # Convert ciphertext to 0-25.
        k = ord(key[i % len(key)]) - ord("a")  # Get current key shift.
        result += chr(((c - k) % 26) + ord("a"))  # Reverse the shift.
    return result  # Return recovered plaintext.


def autokey_encrypt(text, first_key):  # Autokey uses one numeric key then plaintext letters as later keys.
    text = clean_letters(text)  # Normalize plaintext.
    nums = [ord(ch) - ord("a") for ch in text]  # Convert plaintext to numeric values.
    key_stream = [first_key] + nums[:-1]  # First key is given; later keys come from plaintext.
    result = ""  # Store ciphertext.
    for p, k in zip(nums, key_stream):  # Pair plaintext value with key value.
        result += chr(((p + k) % 26) + ord("a"))  # Encrypt using C=(P+K) mod 26.
    return result  # Return ciphertext.


def autokey_decrypt(ciphertext, first_key):  # Autokey decryption rebuilds the keystream as plaintext appears.
    ciphertext = clean_letters(ciphertext)  # Normalize ciphertext.
    recovered = []  # Store numeric plaintext values.
    for i, ch in enumerate(ciphertext):  # Process one ciphertext character at a time.
        c = ord(ch) - ord("a")  # Convert ciphertext to 0-25.
        k = first_key if i == 0 else recovered[i - 1]  # First key is supplied; later key is previous plaintext.
        p = (c - k) % 26  # Recover plaintext number.
        recovered.append(p)  # Save it for output and later keystream use.
    return "".join(chr(p + ord("a")) for p in recovered)  # Convert numeric plaintext back to letters.


def build_playfair_matrix(keyword):  # Create the 5x5 Playfair matrix using I/J together.
    keyword = clean_letters(keyword).replace("j", "i")  # Normalize key and merge j with i.
    alphabet = "abcdefghiklmnopqrstuvwxyz"  # Playfair alphabet omits j.
    seen = []  # Keep characters in insertion order without duplicates.
    for ch in keyword + alphabet:  # Start with keyword then fill remaining letters.
        if ch not in seen:  # Only insert each letter once.
            seen.append(ch)  # Add unseen letter.
    matrix = [seen[i:i + 5] for i in range(0, 25, 5)]  # Split 25 letters into 5 rows.
    return matrix  # Return the completed 5x5 matrix.


def playfair_prepare(text):  # Convert plaintext into Playfair digraphs.
    text = clean_letters(text).replace("j", "i")  # Normalize and merge j with i.
    pairs = []  # Store two-letter blocks.
    i = 0  # Start from first plaintext character.
    while i < len(text):  # Continue until all letters are consumed.
        a = text[i]  # First letter of pair.
        b = text[i + 1] if i + 1 < len(text) else "x"  # Use x if final letter has no partner.
        if a == b:  # Repeated letters cannot share a Playfair pair.
            pairs.append(a + "x")  # Insert x between repeated letters.
            i += 1  # Move only one step because b must be reconsidered.
        else:  # Normal two-different-letter pair.
            pairs.append(a + b)  # Store pair directly.
            i += 2  # Consume both letters.
    return pairs  # Return all digraphs.


def playfair_position(matrix, ch):  # Find the row and column of a letter in the matrix.
    for r in range(5):  # Check every row.
        for c in range(5):  # Check every column.
            if matrix[r][c] == ch:  # Stop when the letter is found.
                return r, c  # Return row and column.
    raise ValueError("Character not present in Playfair matrix.")  # Safety error.


def playfair_encrypt(text, keyword):  # Encrypt text using Playfair rules.
    matrix = build_playfair_matrix(keyword)  # Build the key matrix.
    pairs = playfair_prepare(text)  # Split plaintext into legal pairs.
    result = ""  # Store ciphertext.
    for pair in pairs:  # Encrypt each digraph.
        a, b = pair[0], pair[1]  # Separate the two letters.
        r1, c1 = playfair_position(matrix, a)  # Locate first letter.
        r2, c2 = playfair_position(matrix, b)  # Locate second letter.
        if r1 == r2:  # Same row case.
            result += matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5]  # Move right.
        elif c1 == c2:  # Same column case.
            result += matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2]  # Move down.
        else:  # Rectangle case.
            result += matrix[r1][c2] + matrix[r2][c1]  # Take opposite rectangle corners.
    return result, matrix  # Return ciphertext and matrix for display.


def playfair_decrypt(ciphertext, keyword):  # Reverse the Playfair rules.
    matrix = build_playfair_matrix(keyword)  # Rebuild the same key matrix.
    ciphertext = clean_letters(ciphertext).replace("j", "i")  # Normalize ciphertext.
    result = ""  # Store recovered plaintext including filler x if present.
    for i in range(0, len(ciphertext), 2):  # Process ciphertext in pairs.
        a, b = ciphertext[i], ciphertext[i + 1]  # Extract one pair.
        r1, c1 = playfair_position(matrix, a)  # Locate first letter.
        r2, c2 = playfair_position(matrix, b)  # Locate second letter.
        if r1 == r2:  # Same row case.
            result += matrix[r1][(c1 - 1) % 5] + matrix[r2][(c2 - 1) % 5]  # Move left.
        elif c1 == c2:  # Same column case.
            result += matrix[(r1 - 1) % 5][c1] + matrix[(r2 - 1) % 5][c2]  # Move up.
        else:  # Rectangle case.
            result += matrix[r1][c2] + matrix[r2][c1]  # Swap columns.
    return result  # Return decrypted text.


def matrix_det_2x2(k):  # Compute determinant of a 2x2 Hill key matrix.
    return k[0][0] * k[1][1] - k[0][1] * k[1][0]  # ad-bc.


def hill_inverse_key_2x2(k):  # Compute inverse of a 2x2 matrix modulo 26.
    det = matrix_det_2x2(k) % 26  # Reduce determinant modulo 26.
    det_inv = pow(det, -1, 26)  # Find multiplicative inverse of determinant.
    inv = [[k[1][1], -k[0][1]], [-k[1][0], k[0][0]]]  # Form adjugate matrix.
    return [[(det_inv * inv[r][c]) % 26 for c in range(2)] for r in range(2)]  # Multiply by det inverse.


def hill_encrypt_2x2(text, key_matrix):  # Encrypt text using a 2x2 Hill matrix.
    text = clean_letters(text)  # Normalize plaintext.
    if len(text) % 2 == 1:  # Hill 2x2 needs pairs of letters.
        text += "x"  # Add filler x if length is odd.
    result = ""  # Store ciphertext.
    for i in range(0, len(text), 2):  # Process two letters at a time.
        p0 = ord(text[i]) - ord("a")  # First numeric plaintext symbol.
        p1 = ord(text[i + 1]) - ord("a")  # Second numeric plaintext symbol.
        c0 = (key_matrix[0][0] * p0 + key_matrix[0][1] * p1) % 26  # First output component.
        c1 = (key_matrix[1][0] * p0 + key_matrix[1][1] * p1) % 26  # Second output component.
        result += chr(c0 + ord("a")) + chr(c1 + ord("a"))  # Convert both values to letters.
    return result  # Return ciphertext.


def hill_decrypt_2x2(ciphertext, key_matrix):  # Decrypt text using inverse Hill matrix.
    inv_key = hill_inverse_key_2x2(key_matrix)  # Compute inverse key matrix modulo 26.
    return hill_encrypt_2x2(ciphertext, inv_key)  # Encryption with inverse key performs decryption.


def additive_bruteforce(ciphertext):  # Try all 26 Caesar/additive keys.
    candidates = {}  # Store key -> possible plaintext.
    for key in range(26):  # Test every shift.
        candidates[key] = additive_decrypt(ciphertext, key)  # Decrypt with current key.
    return candidates  # Return all possible answers for human inspection.


def affine_keys_from_known_pair(p1, c1, p2, c2):  # Recover affine keys from two known plaintext-ciphertext mappings.
    P1 = ord(p1.lower()) - ord("a")  # Convert first plaintext letter to number.
    C1 = ord(c1.lower()) - ord("a")  # Convert first ciphertext letter to number.
    P2 = ord(p2.lower()) - ord("a")  # Convert second plaintext letter to number.
    C2 = ord(c2.lower()) - ord("a")  # Convert second ciphertext letter to number.
    answers = []  # Store all valid (a,b) pairs.
    for a in range(26):  # Try every possible multiplicative part.
        if math.gcd(a, 26) != 1:  # Skip non-invertible a values.
            continue  # Move to next a.
        for b in range(26):  # Try every additive part.
            if (a * P1 + b) % 26 == C1 and (a * P2 + b) % 26 == C2:  # Check both known mappings.
                answers.append((a, b))  # Save valid key pair.
    return answers  # Return matching affine keys.


# ============================================================
# LAB 2 — DES / AES / 3DES / MODES / PERFORMANCE
# ============================================================

def aes_key_from_hex(hex_key):  # Convert hex string to raw AES key bytes.
    key = bytes.fromhex(hex_key)  # Interpret each two hex digits as one byte.
    if len(key) not in (16, 24, 32):  # AES accepts 128, 192 or 256 bit keys only.
        raise ValueError("AES key must be 16, 24 or 32 bytes.")  # Reject wrong key length.
    return key  # Return validated key.


def aes_cbc_encrypt(plaintext, key, iv=None):  # AES CBC encryption for text/bytes.
    if isinstance(plaintext, str):  # Convert normal string input to bytes.
        plaintext = plaintext.encode()  # UTF-8 encode the text.
    if iv is None:  # Generate IV automatically when none is supplied.
        iv = get_random_bytes(16)  # AES block size is 16 bytes.
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Create AES-CBC cipher object.
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))  # Pad then encrypt.
    return ciphertext, iv  # Return encrypted bytes and IV.


def aes_cbc_decrypt(ciphertext, key, iv):  # AES CBC decryption.
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Recreate cipher using same key and IV.
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)  # Decrypt then remove padding.
    return plaintext  # Return original bytes.


def aes_ctr_encrypt(plaintext, key, nonce=None):  # AES CTR encryption.
    if isinstance(plaintext, str):  # Convert string to bytes if necessary.
        plaintext = plaintext.encode()  # UTF-8 encoding.
    if nonce is None:  # Generate nonce automatically when absent.
        nonce = get_random_bytes(8)  # 8-byte nonce leaves space for counter in PyCryptodome.
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)  # Create AES-CTR cipher.
    ciphertext = cipher.encrypt(plaintext)  # CTR mode does not require padding.
    return ciphertext, nonce  # Return ciphertext and nonce.


def aes_ctr_decrypt(ciphertext, key, nonce):  # AES CTR decryption uses same stream operation.
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)  # Recreate stream with same key and nonce.
    return cipher.decrypt(ciphertext)  # Recover plaintext bytes.


def des_encrypt(plaintext, key8, iv=None):  # DES CBC encryption using an 8-byte key.
    if isinstance(plaintext, str):  # Convert string input to bytes.
        plaintext = plaintext.encode()  # UTF-8 encode plaintext.
    if isinstance(key8, str):  # Allow easy string keys such as "A1B2C3D4".
        key8 = key8.encode()  # Convert the key string to bytes.
    if len(key8) != 8:  # DES requires exactly 8 key bytes.
        raise ValueError("DES key must be exactly 8 bytes.")  # Reject invalid length.
    if iv is None:  # Generate IV if user did not supply one.
        iv = get_random_bytes(8)  # DES block size is 8 bytes.
    if isinstance(iv, str):  # Allow IV as text such as "12345678".
        iv = iv.encode()  # Convert IV string to bytes.
    cipher = DES.new(key8, DES.MODE_CBC, iv)  # Create DES-CBC cipher.
    ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))  # Pad and encrypt.
    return ciphertext, iv  # Return ciphertext and IV.


def des_decrypt(ciphertext, key8, iv):  # DES CBC decryption.
    if isinstance(key8, str):  # Convert string key to bytes.
        key8 = key8.encode()  # Encode the key.
    if isinstance(iv, str):  # Convert string IV to bytes.
        iv = iv.encode()  # Encode the IV.
    cipher = DES.new(key8, DES.MODE_CBC, iv)  # Recreate DES cipher.
    return unpad(cipher.decrypt(ciphertext), DES.block_size)  # Decrypt and remove padding.


def triple_des_encrypt(plaintext, key):  # Encrypt using Triple DES.
    if isinstance(plaintext, str):  # Convert text to bytes.
        plaintext = plaintext.encode()  # UTF-8 encoding.
    if isinstance(key, str):  # Accept text key.
        key = key.encode()  # Convert key to bytes.
    key = DES3.adjust_key_parity(key)  # Fix parity bits required by DES3.
    iv = get_random_bytes(8)  # 3DES uses 8-byte block/IV.
    cipher = DES3.new(key, DES3.MODE_CBC, iv)  # Create 3DES-CBC cipher.
    ciphertext = cipher.encrypt(pad(plaintext, DES3.block_size))  # Pad and encrypt.
    return ciphertext, iv, key  # Return ciphertext, IV and adjusted key.


def triple_des_decrypt(ciphertext, key, iv):  # Decrypt Triple DES ciphertext.
    cipher = DES3.new(key, DES3.MODE_CBC, iv)  # Recreate 3DES cipher.
    return unpad(cipher.decrypt(ciphertext), DES3.block_size)  # Decrypt and unpad.


def compare_crypto_time(message):  # Compare DES and AES-256 encryption/decryption speed.
    des_key = b"A1B2C3D4"  # Example 8-byte DES key.
    aes_key = get_random_bytes(32)  # Generate a 256-bit AES key.
    start = time.perf_counter()  # Start DES encryption timer.
    des_ct, des_iv = des_encrypt(message, des_key)  # Encrypt with DES.
    des_enc_time = time.perf_counter() - start  # Stop DES encryption timer.
    start = time.perf_counter()  # Start DES decryption timer.
    des_pt = des_decrypt(des_ct, des_key, des_iv)  # Decrypt with DES.
    des_dec_time = time.perf_counter() - start  # Stop DES decryption timer.
    start = time.perf_counter()  # Start AES encryption timer.
    aes_ct, aes_iv = aes_cbc_encrypt(message, aes_key)  # Encrypt with AES-256.
    aes_enc_time = time.perf_counter() - start  # Stop AES encryption timer.
    start = time.perf_counter()  # Start AES decryption timer.
    aes_pt = aes_cbc_decrypt(aes_ct, aes_key, aes_iv)  # Decrypt with AES-256.
    aes_dec_time = time.perf_counter() - start  # Stop AES decryption timer.
    return {  # Return all timing and correctness values.
        "DES encryption time": des_enc_time,  # DES encryption duration.
        "DES decryption time": des_dec_time,  # DES decryption duration.
        "AES-256 encryption time": aes_enc_time,  # AES encryption duration.
        "AES-256 decryption time": aes_dec_time,  # AES decryption duration.
        "DES recovered": des_pt.decode(),  # Show DES recovered message.
        "AES recovered": aes_pt.decode(),  # Show AES recovered message.
    }  # Finish result dictionary.


# ============================================================
# LAB 3 — RSA / ELGAMAL / ECC-LIKE HYBRID / DIFFIE-HELLMAN
# ============================================================

def rsa_generate(bits=2048):  # Generate RSA public/private key pair.
    private_key = RSA.generate(bits)  # Create a fresh RSA private key.
    public_key = private_key.publickey()  # Derive public key from private key.
    return public_key, private_key  # Return public key first, private key second.


def rsa_encrypt_bytes(data, public_key):  # RSA-OAEP encrypt bytes.
    if isinstance(data, str):  # Convert text to bytes.
        data = data.encode()  # UTF-8 encode.
    cipher = PKCS1_OAEP.new(public_key)  # Create RSA OAEP encryptor.
    return cipher.encrypt(data)  # Encrypt and return ciphertext bytes.


def rsa_decrypt_bytes(ciphertext, private_key):  # RSA-OAEP decrypt bytes.
    cipher = PKCS1_OAEP.new(private_key)  # Create RSA OAEP decryptor.
    return cipher.decrypt(ciphertext)  # Recover original bytes.


def rsa_encrypt_long_message(data, public_key):  # Encrypt a longer message by RSA chunking for lab demonstration.
    if isinstance(data, str):  # Convert text to bytes.
        data = data.encode()  # UTF-8 encode.
    key_bytes = public_key.size_in_bytes()  # Find RSA modulus size in bytes.
    max_chunk = key_bytes - 2 * SHA256.digest_size - 2  # OAEP-SHA1 default differs, so keep chunks conservative.
    max_chunk = min(max_chunk, 190)  # 190 bytes safely fits common 2048-bit OAEP defaults.
    chunks = [data[i:i + max_chunk] for i in range(0, len(data), max_chunk)]  # Split message.
    return [rsa_encrypt_bytes(chunk, public_key) for chunk in chunks]  # Encrypt every chunk.


def rsa_decrypt_long_message(chunks, private_key):  # Decrypt list of RSA chunks.
    return b"".join(rsa_decrypt_bytes(chunk, private_key) for chunk in chunks)  # Decrypt and join all chunks.


def rsa_sign_sha256(data, private_key):  # Hash data with SHA-256 and sign the hash using RSA private key.
    if isinstance(data, str):  # Convert text to bytes when needed.
        data = data.encode()  # UTF-8 encode.
    digest = SHA256.new(data)  # Compute SHA-256 digest object.
    signature = pkcs1_15.new(private_key).sign(digest)  # Sign digest using RSA private key.
    return signature  # Return digital signature bytes.


def rsa_verify_sha256(data, signature, public_key):  # Verify RSA signature using public key.
    if isinstance(data, str):  # Convert text to bytes when needed.
        data = data.encode()  # UTF-8 encode.
    digest = SHA256.new(data)  # Recompute SHA-256 over received data.
    try:  # Verification raises an error if signature is bad.
        pkcs1_15.new(public_key).verify(digest, signature)  # Check signature against hash.
        return True  # Signature is authentic and data matches.
    except (ValueError, TypeError):  # Catch invalid-signature errors.
        return False  # Verification failed.


def elgamal_generate(p=7919, g=2, x=None):  # Generate simple ElGamal keys using a prime p and generator g.
    if x is None:  # Generate private key when one is not supplied.
        x = random.randint(2, p - 2)  # Choose private key in valid range.
    y = pow(g, x, p)  # Compute public component y=g^x mod p.
    return (p, g, y), x  # Return public key tuple and private key x.


def elgamal_encrypt_int(m, public_key, k=None):  # Encrypt one integer m where 0 <= m < p.
    p, g, y = public_key  # Unpack ElGamal public parameters.
    if not (0 <= m < p):  # Message must fit modulo p.
        raise ValueError("ElGamal integer message must satisfy 0 <= m < p.")  # Reject too-large integer.
    if k is None:  # Generate ephemeral key when not provided.
        k = random.randint(2, p - 2)  # Choose temporary secret.
    c1 = pow(g, k, p)  # Compute c1=g^k mod p.
    s = pow(y, k, p)  # Compute shared masking value y^k mod p.
    c2 = (m * s) % p  # Mask message to form c2.
    return (c1, c2)  # Return ElGamal ciphertext pair.


def elgamal_decrypt_int(ciphertext, p, x):  # Decrypt one ElGamal integer ciphertext.
    c1, c2 = ciphertext  # Unpack ciphertext pair.
    s = pow(c1, x, p)  # Recompute shared secret.
    s_inv = inverse(s, p)  # Find modular inverse of shared secret.
    return (c2 * s_inv) % p  # Recover original integer.


def elgamal_encrypt_text(text, public_key):  # Encrypt text character-by-character for simple lab use.
    return [elgamal_encrypt_int(ord(ch), public_key) for ch in text]  # Encrypt each Unicode code point.


def elgamal_decrypt_text(cipher_list, p, x):  # Decrypt list of ElGamal character ciphertexts.
    return "".join(chr(elgamal_decrypt_int(pair, p, x)) for pair in cipher_list)  # Recover every character.


def dh_generate_public(p, g, private=None):  # Generate one Diffie-Hellman public/private pair.
    if private is None:  # Generate private value when none is supplied.
        private = random.randint(2, p - 2)  # Choose secret exponent.
    public = pow(g, private, p)  # Compute public value g^private mod p.
    return public, private  # Return public and private values.


def dh_shared_secret(other_public, private, p):  # Compute Diffie-Hellman shared secret.
    return pow(other_public, private, p)  # Raise other side's public value to our private exponent.


def dh_demo(p=7919, g=2):  # Complete Alice-Bob Diffie-Hellman demonstration.
    alice_public, alice_private = dh_generate_public(p, g)  # Generate Alice's values.
    bob_public, bob_private = dh_generate_public(p, g)  # Generate Bob's values.
    alice_secret = dh_shared_secret(bob_public, alice_private, p)  # Alice computes shared secret.
    bob_secret = dh_shared_secret(alice_public, bob_private, p)  # Bob computes shared secret.
    return {  # Return everything needed for lab output.
        "p": p,  # Prime modulus.
        "g": g,  # Generator.
        "alice_public": alice_public,  # Alice's shareable public value.
        "bob_public": bob_public,  # Bob's shareable public value.
        "alice_secret": alice_secret,  # Alice's computed secret.
        "bob_secret": bob_secret,  # Bob's computed secret.
        "match": alice_secret == bob_secret,  # Both secrets must be equal.
    }  # End dictionary.


# ============================================================
# LAB 4 — RABIN / KEY MANAGEMENT / RBAC / AUDIT LOGGING
# ============================================================

def extended_gcd(a, b):  # Return gcd and Bezout coefficients used by Rabin CRT.
    if b == 0:  # Base case of Euclidean algorithm.
        return a, 1, 0  # gcd=a and coefficients 1,0.
    g, x1, y1 = extended_gcd(b, a % b)  # Recursively solve smaller problem.
    x = y1  # Update coefficient for a.
    y = x1 - (a // b) * y1  # Update coefficient for b.
    return g, x, y  # Return gcd and coefficients.


def rabin_generate_small(p=499, q=547):  # Generate simple Rabin key pair; p and q should both be 3 mod 4.
    if p % 4 != 3 or q % 4 != 3:  # Rabin shortcut requires Blum primes.
        raise ValueError("Choose p and q such that p % 4 == q % 4 == 3.")  # Enforce condition.
    n = p * q  # Public modulus.
    return n, (p, q)  # Public key is n; private key is p,q.


def rabin_encrypt_int(m, n):  # Rabin encryption: c=m^2 mod n.
    return pow(m, 2, n)  # Square plaintext modulo n.


def rabin_decrypt_roots(c, private_key):  # Rabin decryption produces four possible roots.
    p, q = private_key  # Unpack private primes.
    n = p * q  # Recompute modulus.
    mp = pow(c, (p + 1) // 4, p)  # Root modulo p.
    mq = pow(c, (q + 1) // 4, q)  # Root modulo q.
    _, yp, yq = extended_gcd(p, q)  # Compute CRT coefficients where yp*p + yq*q = 1.
    r1 = (yp * p * mq + yq * q * mp) % n  # First root.
    r2 = (-r1) % n  # Second root.
    r3 = (yp * p * mq - yq * q * mp) % n  # Third root.
    r4 = (-r3) % n  # Fourth root.
    return [r1, r2, r3, r4]  # Original message is one of these roots.


def timestamp_now():  # Return a human-readable timestamp.
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Format current local date/time.


def audit_log(logs, action, actor, status):  # Add one audit record to a list.
    logs.append({  # Store event as a dictionary.
        "time": timestamp_now(),  # Record event time.
        "actor": actor,  # Record who performed the action.
        "action": action,  # Record what they attempted.
        "status": status,  # Record success/failure.
    })  # Finish log entry.


def rbac_allowed(role, action, permissions):  # Generic Role-Based Access Control check.
    return action in permissions.get(role, set())  # Allow action only if role's permission set contains it.


class SimpleKeyManager:  # Small reusable key-management example for Lab 4 scenarios.
    def __init__(self):  # Initialize storage.
        self.keys = {}  # Maps entity name to key information.
        self.revoked = set()  # Stores revoked entity names.
        self.logs = []  # Stores key-management audit events.

    def generate_rsa_for(self, entity, bits=2048):  # Generate RSA keys for one subsystem/facility.
        public_key, private_key = rsa_generate(bits)  # Generate a fresh RSA pair.
        self.keys[entity] = {"public": public_key, "private": private_key, "created": timestamp_now()}  # Store keys.
        self.revoked.discard(entity)  # New key makes entity active again.
        audit_log(self.logs, "generate_key", entity, "SUCCESS")  # Log generation.
        return public_key, private_key  # Return generated pair.

    def revoke(self, entity):  # Revoke an entity's key.
        if entity in self.keys:  # Only revoke known entities.
            self.revoked.add(entity)  # Mark entity revoked.
            audit_log(self.logs, "revoke_key", entity, "SUCCESS")  # Log revocation.
            return True  # Report success.
        audit_log(self.logs, "revoke_key", entity, "FAILED")  # Log failed attempt.
        return False  # Entity did not exist.

    def get_public(self, entity):  # Return public key if entity is active.
        if entity in self.revoked:  # Do not distribute key for revoked entity.
            raise PermissionError("Key has been revoked.")  # Block access.
        return self.keys[entity]["public"]  # Public keys may be shared.

    def get_private(self, entity, authorized=False):  # Private keys require explicit authorization.
        if not authorized:  # Enforce access control.
            raise PermissionError("Private key access denied.")  # Block unauthorized access.
        if entity in self.revoked:  # Also block revoked keys.
            raise PermissionError("Key has been revoked.")  # Stop use.
        return self.keys[entity]["private"]  # Return private key only to authorized caller.


# ============================================================
# LAB 5 — HASHING
# ============================================================

def custom_hash_5381(text):  # Manual's user-defined hash starting from 5381.
    h = 5381  # Initial hash value required by the manual.
    for ch in text:  # Process one input character at a time.
        h = ((h * 33) + ord(ch)) & 0xFFFFFFFF  # Multiply by 33, add ASCII value, keep 32 bits.
        h ^= (h >> 16)  # Mix upper bits into lower bits.
    return h & 0xFFFFFFFF  # Return final 32-bit hash value.


def sha256_hex(data):  # Compute SHA-256 in hexadecimal form.
    if isinstance(data, str):  # Convert text to bytes.
        data = data.encode()  # UTF-8 encode.
    return hashlib.sha256(data).hexdigest()  # Return 64-character SHA-256 hex string.


def md5_hex(data):  # Compute MD5 hash for lab comparison only.
    if isinstance(data, str):  # Convert text to bytes.
        data = data.encode()  # UTF-8 encode.
    return hashlib.md5(data).hexdigest()  # Return MD5 hex digest.


def sha1_hex(data):  # Compute SHA-1 hash for lab comparison only.
    if isinstance(data, str):  # Convert text to bytes.
        data = data.encode()  # UTF-8 encode.
    return hashlib.sha1(data).hexdigest()  # Return SHA-1 hex digest.


def generate_random_strings(count=75, length=20):  # Generate random dataset of strings.
    dataset = []  # Store generated strings.
    alphabet = string.ascii_letters + string.digits  # Allowed characters.
    for _ in range(count):  # Generate requested number of strings.
        s = "".join(random.choice(alphabet) for _ in range(length))  # Build one random string.
        dataset.append(s)  # Add it to dataset.
    return dataset  # Return all strings.


def hashing_performance(dataset):  # Measure MD5, SHA-1, SHA-256 time and detect collisions.
    algorithms = {  # Map readable names to hashlib constructors.
        "MD5": hashlib.md5,  # MD5 constructor.
        "SHA-1": hashlib.sha1,  # SHA-1 constructor.
        "SHA-256": hashlib.sha256,  # SHA-256 constructor.
    }  # Finish map.
    report = {}  # Store results for each algorithm.
    for name, constructor in algorithms.items():  # Test one hash algorithm at a time.
        seen = {}  # Map digest to first original string.
        collisions = []  # Store any collision pairs.
        start = time.perf_counter()  # Start timer.
        for s in dataset:  # Hash every string.
            digest = constructor(s.encode()).hexdigest()  # Compute digest.
            if digest in seen and seen[digest] != s:  # Detect same digest from different strings.
                collisions.append((seen[digest], s, digest))  # Save collision.
            else:  # No collision for this digest yet.
                seen[digest] = s  # Remember which string produced it.
        elapsed = time.perf_counter() - start  # Stop timer.
        report[name] = {"time": elapsed, "collisions": collisions, "count": len(dataset)}  # Save report.
    return report  # Return all results.


def integrity_check(data, expected_hash):  # Compare current SHA-256 with stored sender hash.
    current_hash = sha256_hex(data)  # Recompute SHA-256 over received/current data.
    return current_hash == expected_hash, current_hash  # Return validity and recomputed hash.


def hash_server(host="127.0.0.1", port=5000):  # Server for Lab 5 integrity demonstration.
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP socket.
    server.bind((host, port))  # Attach socket to host/port.
    server.listen(1)  # Wait for one client.
    print("Hash server waiting...")  # Display status.
    conn, addr = server.accept()  # Accept incoming connection.
    data = conn.recv(4096)  # Receive message bytes.
    digest = sha256_hex(data)  # Compute SHA-256 on received data.
    conn.sendall(digest.encode())  # Send hash back to client.
    conn.close()  # Close client connection.
    server.close()  # Close server socket.


def hash_client(message, host="127.0.0.1", port=5000):  # Client side of Lab 5 integrity demo.
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP socket.
    client.connect((host, port))  # Connect to server.
    client.sendall(message.encode())  # Send message to server.
    server_hash = client.recv(4096).decode()  # Receive server-computed hash.
    local_hash = sha256_hex(message)  # Compute own hash of original message.
    client.close()  # Close connection.
    return server_hash == local_hash, server_hash, local_hash  # True means no corruption/tampering.


# ============================================================
# LAB 6 — DIGITAL SIGNATURES / SCHNORR / CLIENT-SERVER
# ============================================================

def schnorr_generate(p=23, q=11, g=2, x=None):  # Small Schnorr-style key generation for lab demonstration.
    if x is None:  # Choose private signing key if not supplied.
        x = random.randint(1, q - 1)  # Private key lies in 1..q-1.
    y = pow(g, x, p)  # Compute public value y=g^x mod p.
    return (p, q, g, y), x  # Return public parameters and private key.


def schnorr_sign(message, public_params, private_x):  # Produce a Schnorr-style signature pair (e,s).
    p, q, g, y = public_params  # Unpack public values.
    k = random.randint(1, q - 1)  # Choose fresh random nonce.
    r = pow(g, k, p)  # Compute commitment r=g^k mod p.
    e_bytes = hashlib.sha256((str(r) + "|" + message).encode()).digest()  # Hash commitment and message.
    e = int.from_bytes(e_bytes, "big") % q  # Convert digest to challenge modulo q.
    s = (k + private_x * e) % q  # Compute response value.
    return (e, s)  # Return Schnorr signature.


def schnorr_verify(message, signature, public_params):  # Verify Schnorr-style signature.
    p, q, g, y = public_params  # Unpack public values.
    e, s = signature  # Unpack signature pair.
    y_inv_e = pow(pow(y, e, p), -1, p)  # Compute y^(-e) mod p.
    r_prime = (pow(g, s, p) * y_inv_e) % p  # Reconstruct commitment.
    e_bytes = hashlib.sha256((str(r_prime) + "|" + message).encode()).digest()  # Recompute challenge.
    e_prime = int.from_bytes(e_bytes, "big") % q  # Reduce challenge modulo q.
    return e_prime == e  # Valid only if recomputed challenge matches signature challenge.


def signature_server(host="127.0.0.1", port=5001):  # Example server that verifies RSA-signed data.
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP socket.
    server.bind((host, port))  # Attach server to network endpoint.
    server.listen(1)  # Wait for one client.
    conn, addr = server.accept()  # Accept connection.
    length = int.from_bytes(conn.recv(4), "big")  # Read message length.
    message = conn.recv(length)  # Read message bytes.
    sig_length = int.from_bytes(conn.recv(4), "big")  # Read signature length.
    signature = conn.recv(sig_length)  # Read signature bytes.
    key_length = int.from_bytes(conn.recv(4), "big")  # Read public-key length.
    public_pem = conn.recv(key_length)  # Read sender public key.
    public_key = RSA.import_key(public_pem)  # Parse sender public key.
    valid = rsa_verify_sha256(message, signature, public_key)  # Verify RSA signature.
    conn.sendall(b"VALID" if valid else b"INVALID")  # Send verification result.
    conn.close()  # Close client connection.
    server.close()  # Close server socket.


def signature_client(message, private_key, host="127.0.0.1", port=5001):  # Example client that signs and sends data.
    message_bytes = message.encode()  # Convert text to bytes.
    signature = rsa_sign_sha256(message_bytes, private_key)  # Sign message hash.
    public_pem = private_key.publickey().export_key()  # Export public key for receiver.
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP socket.
    client.connect((host, port))  # Connect to server.
    client.sendall(len(message_bytes).to_bytes(4, "big"))  # Send message length.
    client.sendall(message_bytes)  # Send message.
    client.sendall(len(signature).to_bytes(4, "big"))  # Send signature length.
    client.sendall(signature)  # Send signature.
    client.sendall(len(public_pem).to_bytes(4, "big"))  # Send public-key length.
    client.sendall(public_pem)  # Send public key.
    result = client.recv(1024).decode()  # Receive VALID/INVALID.
    client.close()  # Close connection.
    return result  # Return server response.


# ============================================================
# FILE HELPERS FOR SCENARIO QUESTIONS
# ============================================================

def write_text_file(filename, content):  # Create/overwrite a text file.
    Path(filename).write_text(content, encoding="utf-8")  # Save text using UTF-8.


def read_text_file(filename):  # Read a text file completely.
    return Path(filename).read_text(encoding="utf-8")  # Return file contents as string.


def write_binary_file(filename, data):  # Create/overwrite a binary file.
    Path(filename).write_bytes(data)  # Save bytes exactly as given.


def read_binary_file(filename):  # Read a binary file completely.
    return Path(filename).read_bytes()  # Return raw bytes.


# ============================================================
# READY-MADE MANUAL QUESTION WRAPPERS
# ============================================================

def lab1_q1_demo():  # Manual Lab 1 Q1: additive, multiplicative and affine on same message.
    message = "I am learning information security"  # Given plaintext.
    add_ct = additive_encrypt(message, 20)  # Encrypt using additive key 20.
    add_pt = additive_decrypt(add_ct, 20)  # Decrypt additive ciphertext.
    mul_ct = multiplicative_encrypt(message, 15)  # Encrypt using multiplicative key 15.
    mul_pt = multiplicative_decrypt(mul_ct, 15)  # Decrypt multiplicative ciphertext.
    aff_ct = affine_encrypt(message, 15, 20)  # Encrypt using affine key (15,20).
    aff_pt = affine_decrypt(aff_ct, 15, 20)  # Decrypt affine ciphertext.
    return {"add": (add_ct, add_pt), "mul": (mul_ct, mul_pt), "affine": (aff_ct, aff_pt)}  # Return all results.


def lab1_q2_demo():  # Manual Lab 1 Q2: Vigenere and Autokey.
    message = "the house is being sold tonight"  # Given plaintext.
    vig_ct = vigenere_encrypt(message, "dollars")  # Vigenere encryption with keyword dollars.
    vig_pt = vigenere_decrypt(vig_ct, "dollars")  # Vigenere decryption.
    auto_ct = autokey_encrypt(message, 7)  # Autokey encryption with initial key 7.
    auto_pt = autokey_decrypt(auto_ct, 7)  # Autokey decryption.
    return {"vigenere": (vig_ct, vig_pt), "autokey": (auto_ct, auto_pt)}  # Return results.


def lab1_q3_demo():  # Manual Lab 1 Q3: Playfair with key GUIDANCE.
    message = "The key is hidden under the door pad"  # Given plaintext.
    ciphertext, matrix = playfair_encrypt(message, "GUIDANCE")  # Encrypt using Playfair.
    plaintext = playfair_decrypt(ciphertext, "GUIDANCE")  # Decrypt the ciphertext.
    return {"matrix": matrix, "ciphertext": ciphertext, "decrypted": plaintext}  # Return matrix and texts.


def lab1_q4_demo():  # Manual Lab 1 Q4: Hill cipher using 2x2 key [[3,3],[2,7]].
    key = [[3, 3], [2, 7]]  # Given Hill key matrix.
    message = "We live in an insecure world"  # Given plaintext.
    ciphertext = hill_encrypt_2x2(message, key)  # Encrypt plaintext.
    plaintext = hill_decrypt_2x2(ciphertext, key)  # Decrypt ciphertext.
    return ciphertext, plaintext  # Return both values.


def lab1_q6_affine_attack_demo():  # Manual attack: plaintext "ab" maps to ciphertext "GL".
    keys = affine_keys_from_known_pair("a", "G", "b", "L")  # Recover affine key candidates.
    ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"  # Given ciphertext.
    answers = []  # Store each key and corresponding plaintext.
    for a, b in keys:  # Try every recovered candidate.
        answers.append(((a, b), affine_decrypt(ciphertext, a, b)))  # Decrypt with candidate key.
    return answers  # Return likely solution(s).


def lab2_des_demo():  # Manual Lab 2 Q1: DES encrypt/decrypt "Confidential Data".
    ciphertext, iv = des_encrypt("Confidential Data", "A1B2C3D4")  # Encrypt with given DES key.
    plaintext = des_decrypt(ciphertext, "A1B2C3D4", iv)  # Decrypt using same key and IV.
    return ciphertext.hex(), iv.hex(), plaintext.decode()  # Return readable values.


def lab2_aes128_demo():  # Manual Lab 2 Q2: AES-128 encrypt/decrypt.
    key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")  # 32 hex digits = 16 bytes = AES-128.
    ciphertext, iv = aes_cbc_encrypt("Sensitive Information", key)  # Encrypt message.
    plaintext = aes_cbc_decrypt(ciphertext, key, iv)  # Decrypt message.
    return ciphertext.hex(), iv.hex(), plaintext.decode()  # Return readable output.


def lab2_3des_demo():  # Manual Lab 2 Q4: Triple DES.
    raw_key = bytes.fromhex("1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF")  # 24-byte 3DES key from hex.
    ciphertext, iv, key = triple_des_encrypt("Classified Text", raw_key)  # Encrypt using 3DES.
    plaintext = triple_des_decrypt(ciphertext, key, iv)  # Decrypt ciphertext.
    return ciphertext.hex(), iv.hex(), plaintext.decode()  # Return output.


def lab2_aes256_demo():  # Manual additional AES-256 question.
    key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")  # 64 hex digits = 32 bytes.
    ciphertext, iv = aes_cbc_encrypt("Encryption Strength", key)  # AES-256 encryption.
    plaintext = aes_cbc_decrypt(ciphertext, key, iv)  # AES-256 decryption.
    return ciphertext.hex(), iv.hex(), plaintext.decode()  # Return readable output.


def lab2_des_cbc_demo():  # Manual additional DES CBC question.
    ciphertext, iv = des_encrypt("Secure Communication", "A1B2C3D4", "12345678")  # DES-CBC with supplied IV.
    plaintext = des_decrypt(ciphertext, "A1B2C3D4", iv)  # Decrypt ciphertext.
    return ciphertext.hex(), plaintext.decode()  # Return ciphertext and recovered message.


def lab2_aes_ctr_demo():  # Manual additional AES CTR question.
    key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")  # AES-128 key from given hex.
    nonce = bytes.fromhex("0000000000000000")  # 16 hex digits = 8-byte nonce.
    ciphertext, used_nonce = aes_ctr_encrypt("Cryptography Lab Exercise", key, nonce)  # Encrypt using CTR.
    plaintext = aes_ctr_decrypt(ciphertext, key, used_nonce)  # Decrypt using same key and nonce.
    return ciphertext.hex(), plaintext.decode()  # Return output.


def lab3_rsa_demo():  # Manual Lab 3 Q1: RSA encrypt/decrypt "Asymmetric Encryption".
    public_key, private_key = rsa_generate(2048)  # Generate RSA keys.
    ciphertext = rsa_encrypt_long_message("Asymmetric Encryption", public_key)  # Encrypt message.
    plaintext = rsa_decrypt_long_message(ciphertext, private_key).decode()  # Decrypt message.
    return public_key.export_key().decode(), private_key.export_key().decode(), [c.hex() for c in ciphertext], plaintext  # Return keys and result.


def lab3_elgamal_demo():  # Manual Lab 3 Q3: ElGamal encrypt/decrypt "Confidential Data".
    public_key, private_x = elgamal_generate()  # Generate ElGamal keys.
    ciphertext = elgamal_encrypt_text("Confidential Data", public_key)  # Encrypt each character.
    plaintext = elgamal_decrypt_text(ciphertext, public_key[0], private_x)  # Decrypt message.
    return public_key, private_x, ciphertext, plaintext  # Return all values.


def lab3_fixed_elgamal_demo():  # Manual additional ElGamal with p=7919,g=2,h=6465,x=2999.
    public_key = (7919, 2, 6465)  # Use the exact given public key.
    private_x = 2999  # Use the exact given private key.
    ciphertext = elgamal_encrypt_text("Asymmetric Algorithms", public_key)  # Encrypt message.
    plaintext = elgamal_decrypt_text(ciphertext, 7919, private_x)  # Decrypt message.
    return ciphertext, plaintext  # Return result.


def lab3_diffie_hellman_demo():  # Manual Lab 3 Q5: Diffie-Hellman key exchange.
    start = time.perf_counter()  # Start timer.
    result = dh_demo(7919, 2)  # Perform full key exchange.
    result["time"] = time.perf_counter() - start  # Store total key-exchange time.
    return result  # Return public values, secrets and timing.


def lab4_securecorp_demo():  # Manual Lab 4 Q1 style: RSA + DH + key management.
    km = SimpleKeyManager()  # Create key manager.
    km.generate_rsa_for("Finance")  # Create Finance RSA keys.
    km.generate_rsa_for("HR")  # Create HR RSA keys.
    km.generate_rsa_for("SupplyChain")  # Create Supply Chain RSA keys.
    dh = dh_demo(7919, 2)  # Establish a shared secret example.
    message = "Quarterly secure document"  # Example enterprise document.
    hr_public = km.get_public("HR")  # Obtain HR public key.
    encrypted = rsa_encrypt_bytes(message, hr_public)  # Encrypt document to HR.
    hr_private = km.get_private("HR", authorized=True)  # Authorized HR obtains private key.
    decrypted = rsa_decrypt_bytes(encrypted, hr_private).decode()  # HR decrypts document.
    return {"dh": dh, "decrypted": decrypted, "logs": km.logs}  # Return combined demonstration.


def lab4_rabin_demo():  # Manual Lab 4 Rabin pattern.
    n, private_key = rabin_generate_small()  # Generate Rabin key pair.
    message_integer = 123  # Small example plaintext integer.
    ciphertext = rabin_encrypt_int(message_integer, n)  # Encrypt by squaring mod n.
    roots = rabin_decrypt_roots(ciphertext, private_key)  # Recover four possible roots.
    return {"public_n": n, "private": private_key, "ciphertext": ciphertext, "roots": roots}  # Return values.


def lab5_q1_demo():  # Manual Lab 5 Q1: custom hash starting at 5381.
    message = input("Enter a string: ")  # Ask user for any message.
    value = custom_hash_5381(message)  # Compute manual-defined hash.
    print("32-bit custom hash:", value)  # Display final hash.


def lab5_q3_demo():  # Manual Lab 5 Q3: compare MD5, SHA-1 and SHA-256.
    dataset = generate_random_strings(count=75, length=20)  # Generate 75 random strings.
    return hashing_performance(dataset)  # Return timing/collision report.


def lab6_rsa_signature_demo():  # Manual Lab 6 core: sign and verify a message using RSA.
    public_key, private_key = rsa_generate(2048)  # Generate RSA pair.
    message = "Alice legal document"  # Example document.
    signature = rsa_sign_sha256(message, private_key)  # Alice signs message hash using private key.
    valid = rsa_verify_sha256(message, signature, public_key)  # Bob verifies using Alice public key.
    return signature.hex(), valid  # Return signature and verification status.


def lab6_schnorr_demo():  # Manual Lab 6 Q1: Schnorr signing/verification demonstration.
    public_params, private_x = schnorr_generate()  # Generate Schnorr public/private values.
    message = "Signed document"  # Example message.
    signature = schnorr_sign(message, public_params, private_x)  # Sign message.
    valid = schnorr_verify(message, signature, public_params)  # Verify signature.
    return public_params, private_x, signature, valid  # Return all values.


# ============================================================
# SCENARIO TEMPLATE 1 — HEALTHSECURE (RSA + SHA256 + SIGNATURE + RBAC)
# ============================================================

def healthsecure_demo():  # Demonstrate Doctor/Nurse/Admin permissions using RSA and SHA-256.
    doctor_public, doctor_private = rsa_generate(2048)  # Doctor owns RSA pair.
    records = []  # Store encrypted patient records.
    permissions = {  # Define RBAC permissions for all roles.
        "Doctor": {"create", "view_encrypted", "decrypt", "integrity", "verify_signature"},  # Doctor full authorized operations.
        "Nurse": {"view_encrypted", "integrity", "verify_signature"},  # Nurse cannot decrypt.
        "Admin": {"view_metadata", "verify_signature"},  # Admin sees only metadata and verifies signatures.
    }  # Finish permission table.

    patient = {  # Example patient information.
        "Name": "Riya",  # Patient name.
        "Age": 25,  # Patient age.
        "Gender": "F",  # Patient gender.
        "Blood Group": "O+",  # Patient blood group.
        "Diagnosis": "Example diagnosis",  # Medical diagnosis.
    }  # Finish patient dictionary.

    plaintext = str(patient).encode()  # Convert patient dictionary to bytes for encryption.
    encrypted_chunks = rsa_encrypt_long_message(plaintext, doctor_public)  # Encrypt patient data with Doctor public key.
    encrypted_blob = b"".join(encrypted_chunks)  # Join encrypted chunks only for hashing/storage display.
    stored_hash = sha256_hex(encrypted_blob)  # Hash encrypted data for integrity.
    signature = rsa_sign_sha256(encrypted_blob, doctor_private)  # Sign encrypted-data hash implicitly through SHA-256.
    record = {  # Create stored record.
        "id": 1,  # Record identifier.
        "encrypted_chunks": encrypted_chunks,  # Keep chunks for correct RSA decryption.
        "encrypted_blob": encrypted_blob,  # Keep joined bytes for hashing and display.
        "hash": stored_hash,  # Store sender-side hash.
        "signature": signature,  # Store Doctor's signature.
        "timestamp": timestamp_now(),  # Store creation time.
    }  # Finish record.
    records.append(record)  # Add record to storage.

    integrity_ok, recomputed_hash = integrity_check(record["encrypted_blob"], record["hash"])  # Nurse/Doctor integrity check.
    signature_ok = rsa_verify_sha256(record["encrypted_blob"], record["signature"], doctor_public)  # Verify Doctor authenticity.
    doctor_plaintext = None  # Do not decrypt until checks succeed.
    if integrity_ok and signature_ok:  # Enforce "decrypt/display only if both checks pass".
        doctor_plaintext = rsa_decrypt_long_message(record["encrypted_chunks"], doctor_private).decode()  # Doctor decrypts.
    return {  # Return full demo result.
        "permissions": permissions,  # Show RBAC design.
        "stored_record": record,  # Show encrypted storage.
        "recomputed_hash": recomputed_hash,  # Show receiver-side hash.
        "integrity_ok": integrity_ok,  # Integrity result.
        "signature_ok": signature_ok,  # Authenticity result.
        "doctor_plaintext": doctor_plaintext,  # Plaintext visible only after successful checks.
    }  # Finish result.


# ============================================================
# SCENARIO TEMPLATE 2 — MEDISECURE (AES + SHA256 + RSA SIGNATURE + FILE + RBAC)
# ============================================================

def mediseccure_upload(filename, aes_key, iv, patient_private_key):  # Patient reads file, encrypts, hashes and signs.
    plaintext = read_binary_file(filename)  # Read original medical-record file.
    encrypted, used_iv = aes_cbc_encrypt(plaintext, aes_key, iv)  # Encrypt file using shared AES key and supplied IV.
    digest = sha256_hex(encrypted)  # Compute SHA-256 on encrypted record.
    signature = rsa_sign_sha256(encrypted, patient_private_key)  # Sign encrypted data hash with Patient private key.
    record = {  # Store only the values required by the scenario.
        "filename": filename,  # Original file name.
        "encrypted": encrypted,  # AES ciphertext.
        "hash": digest,  # SHA-256 digest of ciphertext.
        "signature": signature,  # Patient RSA signature.
        "iv": used_iv,  # IV needed by Doctor for AES decryption.
        "timestamp": timestamp_now(),  # Upload time.
    }  # Finish stored record.
    return record  # Return encrypted record object.


def mediseccure_doctor_open(record, aes_key, patient_public_key):  # Doctor verifies before decrypting.
    integrity_ok, current_hash = integrity_check(record["encrypted"], record["hash"])  # Verify ciphertext integrity.
    signature_ok = rsa_verify_sha256(record["encrypted"], record["signature"], patient_public_key)  # Verify Patient signature.
    plaintext = None  # Keep plaintext unavailable until both checks succeed.
    if integrity_ok and signature_ok:  # Decrypt only after successful integrity and authenticity checks.
        plaintext = aes_cbc_decrypt(record["encrypted"], aes_key, record["iv"]).decode()  # Recover medical record.
    return {  # Return Doctor verification result.
        "integrity_ok": integrity_ok,  # Hash-comparison result.
        "signature_ok": signature_ok,  # Signature-verification result.
        "current_hash": current_hash,  # Recomputed hash.
        "plaintext": plaintext,  # Medical content only when valid.
        "verified_at": timestamp_now(),  # Verification timestamp.
    }  # Finish output.


def mediseccure_auditor_view(record, patient_public_key):  # Auditor sees metadata and verifies signature only.
    signature_ok = rsa_verify_sha256(record["encrypted"], record["signature"], patient_public_key)  # Verify signature.
    return {  # Return only permitted Auditor information.
        "filename": record["filename"],  # File identifier.
        "hash": record["hash"],  # Stored SHA-256.
        "timestamp": record["timestamp"],  # Upload time.
        "signature_valid": signature_ok,  # Authenticity result.
    }  # Finish restricted view.


# ============================================================
# SCENARIO TEMPLATE 3 — AES-128 + RSA KEY WRAP + ELGAMAL AUTH CODE + HASH/TAMPER
# ============================================================

def hospital_hybrid_demo():  # Full hybrid hospital scenario matching common midsem style.
    original_filename = "patient_original.txt"  # File to create.
    encrypted_filename = "patient_encrypted.bin"  # File that stores AES ciphertext.
    encrypted_key_filename = "aes_key_rsa.bin"  # File that stores RSA-encrypted AES key.
    write_text_file(original_filename, "Patient: Aarav\nDiagnosis: Example medical record\n")  # Create original file with content.
    plaintext = read_binary_file(original_filename)  # Read original file bytes.

    aes_key = get_random_bytes(16)  # Generate AES-128 key = 16 bytes.
    aes_ciphertext, iv = aes_cbc_encrypt(plaintext, aes_key)  # Encrypt original file with AES-128.
    write_binary_file(encrypted_filename, aes_ciphertext)  # Store AES-encrypted message in another file.

    rsa_public, rsa_private = rsa_generate(2048)  # Generate RSA key pair.
    encrypted_aes_key = rsa_encrypt_bytes(aes_key, rsa_public)  # Protect AES key using RSA public key.
    write_binary_file(encrypted_key_filename, encrypted_aes_key)  # Save RSA-encrypted AES key.

    elgamal_public, elgamal_private = elgamal_generate(7919, 2)  # Generate ElGamal keys.
    authorization_code = "AUTH123"  # Example authorization code; replace with value given in exam.
    encrypted_auth = elgamal_encrypt_text(authorization_code, elgamal_public)  # Encrypt authorization code with ElGamal.

    sender_hash = sha256_hex(aes_ciphertext)  # Sender hashes AES ciphertext.
    receiver_hash = sha256_hex(read_binary_file(encrypted_filename))  # Receiver hashes stored/received ciphertext.
    integrity_ok = sender_hash == receiver_hash  # Same hash means no detected change.

    decrypted_text = None  # Do not decrypt unless integrity succeeds.
    decrypted_aes_key = None  # Do not expose decrypted key unless verification succeeds.
    decrypted_auth = None  # Do not decrypt authorization code unless verification succeeds.
    if integrity_ok:  # Continue only when ciphertext integrity is valid.
        decrypted_aes_key = rsa_decrypt_bytes(encrypted_aes_key, rsa_private)  # Recover AES key using RSA private key.
        decrypted_auth = elgamal_decrypt_text(encrypted_auth, elgamal_public[0], elgamal_private)  # Recover auth code.
        decrypted_text = aes_cbc_decrypt(aes_ciphertext, decrypted_aes_key, iv).decode()  # Recover original file content.

    tampered = bytearray(aes_ciphertext)  # Make mutable copy of ciphertext.
    tampered[0] ^= 1  # Flip one bit to simulate one-character/byte tampering.
    tampered_hash = sha256_hex(bytes(tampered))  # Hash tampered ciphertext.
    tamper_integrity_ok = tampered_hash == sender_hash  # This should be False.

    return {  # Return everything the question asks to display.
        "aes_ciphertext_hex": aes_ciphertext.hex(),  # Encrypted file data.
        "aes_iv_hex": iv.hex(),  # AES IV.
        "rsa_public_key": rsa_public.export_key().decode(),  # RSA public key.
        "rsa_encrypted_aes_key_hex": encrypted_aes_key.hex(),  # RSA-wrapped AES key.
        "elgamal_public_key": elgamal_public,  # ElGamal public values.
        "elgamal_encrypted_auth": encrypted_auth,  # Encrypted authorization code.
        "sender_hash": sender_hash,  # Sender SHA-256.
        "receiver_hash": receiver_hash,  # Receiver SHA-256.
        "integrity_ok": integrity_ok,  # Normal integrity result.
        "decrypted_aes_key_hex": None if decrypted_aes_key is None else decrypted_aes_key.hex(),  # Recovered AES key.
        "decrypted_authorization_code": decrypted_auth,  # Recovered ElGamal code.
        "decrypted_original_content": decrypted_text,  # Recovered patient file content.
        "tampered_hash": tampered_hash,  # Hash after tampering.
        "tamper_integrity_ok": tamper_integrity_ok,  # Should be False.
    }  # Finish output.


# ============================================================
# QUICK MENU — USE THIS AS A STARTING POINT IN THE EXAM
# ============================================================

def quick_menu():  # Small menu for testing the reusable functions.
    while True:  # Keep showing menu until user exits.
        print("\nIS OPEN-BOOK TOOLKIT")  # Menu title.
        print("1. Lab 1 classical cipher demos")  # Option 1.
        print("2. Lab 2 AES/DES demos")  # Option 2.
        print("3. Lab 3 RSA/ElGamal/DH demos")  # Option 3.
        print("4. Lab 4 RSA+DH key-management demo")  # Option 4.
        print("5. Lab 5 hashing comparison")  # Option 5.
        print("6. Lab 6 RSA signature demo")  # Option 6.
        print("7. HealthSecure scenario")  # Option 7.
        print("8. MediSecure scenario instructions")  # Option 8.
        print("9. AES+RSA+ElGamal hybrid hospital scenario")  # Option 9.
        print("0. Exit")  # Exit option.
        choice = input("Enter choice: ").strip()  # Read user choice.

        if choice == "1":  # Run Lab 1 examples.
            print(lab1_q1_demo())  # Show Q1.
            print(lab1_q2_demo())  # Show Q2.
            print(lab1_q3_demo())  # Show Q3.
            print(lab1_q4_demo())  # Show Q4.
        elif choice == "2":  # Run Lab 2 examples.
            print("DES:", lab2_des_demo())  # Show DES result.
            print("AES-128:", lab2_aes128_demo())  # Show AES-128 result.
            print("AES-256:", lab2_aes256_demo())  # Show AES-256 result.
            print("CTR:", lab2_aes_ctr_demo())  # Show AES-CTR result.
        elif choice == "3":  # Run asymmetric demos.
            print("ElGamal:", lab3_elgamal_demo())  # Show ElGamal.
            print("DH:", lab3_diffie_hellman_demo())  # Show Diffie-Hellman.
        elif choice == "4":  # Run key-management demo.
            print(lab4_securecorp_demo())  # Show RSA+DH+logs result.
        elif choice == "5":  # Run hashing comparison.
            print(lab5_q3_demo())  # Display timing/collision report.
        elif choice == "6":  # Run RSA digital signature demo.
            print(lab6_rsa_signature_demo())  # Display signature validity.
        elif choice == "7":  # Run HealthSecure scenario.
            print(healthsecure_demo())  # Display RBAC, integrity and signature result.
        elif choice == "8":  # MediSecure needs a real .txt file, key and IV.
            print("Use mediseccure_upload(), mediseccure_doctor_open(), and mediseccure_auditor_view().")  # Give exact functions.
        elif choice == "9":  # Run hybrid hospital scenario.
            print(hospital_hybrid_demo())  # Display all required values.
        elif choice == "0":  # Exit requested.
            break  # Leave the loop.
        else:  # Invalid menu choice.
            print("Invalid choice.")  # Tell user to try again.


# ============================================================================
# COMPLETE-MANUAL ADDITIONS
# The functions below fill the remaining Lab 1-6 manual exercises so that the
# file can be used as one open-book reference during the midsem.
# ============================================================================

# ---------------------------------------------------------------------------
# LAB 1 — REMAINING ATTACK / ADDITIONAL-EXERCISE HELPERS
# ---------------------------------------------------------------------------

def shift_key_from_known_plaintext(plaintext, ciphertext):  # Recover a Caesar key from a known plaintext/ciphertext pair.
    p = clean_letters(plaintext)  # Remove spaces/punctuation from the known plaintext.
    c = clean_letters(ciphertext)  # Remove spaces/punctuation from the known ciphertext.
    if len(p) != len(c) or len(p) == 0:  # Make sure both known strings have matching usable length.
        raise ValueError("Plaintext and ciphertext must have equal non-zero letter length.")  # Stop if inputs cannot be compared.
    shifts = []  # Store the shift observed at every character position.
    for plain_ch, cipher_ch in zip(p, c):  # Compare corresponding known letters.
        plain_num = ord(plain_ch) - ord('a')  # Convert plaintext letter to 0-25.
        cipher_num = ord(cipher_ch) - ord('a')  # Convert ciphertext letter to 0-25.
        shifts.append((cipher_num - plain_num) % 26)  # Calculate the Caesar shift at this position.
    if len(set(shifts)) != 1:  # A true shift cipher must use one identical shift everywhere.
        raise ValueError("The supplied pair is not consistent with one shift cipher key.")  # Reject inconsistent data.
    return shifts[0]  # Return the recovered shift key.


def keyed_transposition_analysis(plaintext, ciphertext):  # Check a chosen-plaintext keyed-transposition example.
    if len(plaintext) != len(ciphertext):  # A pure permutation must preserve total length.
        return {"consistent": False, "reason": "Lengths are different."}  # Report why it cannot be a simple permutation.
    used = set()  # Remember which plaintext positions have already been used.
    permutation = []  # Store source index for every ciphertext symbol.
    for cipher_ch in ciphertext:  # Inspect each output symbol in order.
        source_index = None  # Assume no matching source position has been found yet.
        for index, plain_ch in enumerate(plaintext):  # Search all plaintext positions.
            if plain_ch == cipher_ch and index not in used:  # Find an unused matching plaintext symbol.
                source_index = index  # Record where this ciphertext symbol came from.
                used.add(index)  # Mark that plaintext position as used.
                break  # Stop searching for this output symbol.
        if source_index is None:  # A symbol that never existed in plaintext cannot come from a permutation.
            return {"consistent": False, "reason": f"Cipher symbol {cipher_ch!r} is absent from the supplied plaintext."}  # Explain inconsistency.
        permutation.append(source_index)  # Save recovered source position.
    return {"consistent": True, "key_size": len(plaintext), "permutation": permutation}  # Return inferred permutation information.


def lab1_q5_known_plaintext_demo():  # Manual Lab 1 Q5: use known pair yes->CIW, then decrypt XVIEWYWI.
    key = shift_key_from_known_plaintext("yes", "CIW")  # Recover the Caesar shift from the known plaintext/ciphertext pair.
    plaintext = additive_decrypt("XVIEWYWI", key)  # Decrypt the literal second ciphertext using the recovered shift.
    return {  # Return all values needed for the answer.
        "attack_type": "Known-plaintext attack",  # The attacker knows a plaintext and its corresponding ciphertext.
        "recovered_shift": key,  # The known pair reveals shift 4.
        "literal_decryption": plaintext,  # The literal manual ciphertext becomes TREASUSE.
        "note": "With shift 4, XVIEWYWI decrypts to TREASUSE; TREASURE would encrypt to XVIEWYVI.",  # Preserve and flag the printed inconsistency.
    }  # Finish result dictionary.


def lab1_additional_additive_bruteforce_demo():  # Manual additional exercise: brute-force the additive cipher near birthday key 13.
    ciphertext = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"  # Use the exact printed ciphertext.
    answers = additive_bruteforce(ciphertext)  # Try every one of the 26 possible additive keys.
    return {key: answers[key] for key in range(10, 17)}  # Return keys near 13 first because the question gives that hint.


def lab1_additional_transposition_attack_demo():  # Manual additional exercise: analyze abcdefghi -> CABDEHFGL.
    analysis = keyed_transposition_analysis("abcdefghi", "CABDEHFGL")  # Test whether the literal strings form a valid permutation.
    return {  # Return the conceptual answer and literal-data analysis.
        "attack_type": "Chosen-plaintext attack",  # Eve deliberately typed a plaintext of her choice.
        "analysis": analysis,  # The literal ciphertext contains a symbol not found in the plaintext.
        "note": "The printed ciphertext contains 'l', which is not in 'abcdefghi', so the literal pair cannot be a pure permutation as written.",  # Flag source inconsistency.
    }  # Finish result.


def lab1_additional_vigenere_health_demo():  # Manual additional exercise: Vigenere with keyword HEALTH.
    message = "Life is full of surprises"  # Use the exact manual plaintext.
    ciphertext = vigenere_encrypt(message, "HEALTH")  # Encrypt using the keyword HEALTH.
    plaintext = vigenere_decrypt(ciphertext, "HEALTH")  # Decrypt to verify recovery.
    return ciphertext, plaintext  # Return encrypted and recovered text.


# ---------------------------------------------------------------------------
# LAB 2 — REMAINING MANUAL EXERCISES
# ---------------------------------------------------------------------------

def des_ecb_encrypt(data, key):  # Encrypt with DES-ECB when a manual question gives no IV/mode.
    if isinstance(data, str):  # Allow ordinary string plaintext.
        data = data.encode()  # Convert text to bytes.
    if isinstance(key, str):  # Allow a normal 8-character key string.
        key = key.encode()  # Convert key to bytes.
    cipher = DES.new(key, DES.MODE_ECB)  # Create DES cipher in ECB mode.
    return cipher.encrypt(pad(data, DES.block_size))  # Pad to 8-byte blocks and encrypt.


def des_ecb_decrypt(ciphertext, key):  # Reverse DES-ECB encryption.
    if isinstance(key, str):  # Allow a string key.
        key = key.encode()  # Convert key to bytes.
    cipher = DES.new(key, DES.MODE_ECB)  # Recreate DES-ECB cipher.
    return unpad(cipher.decrypt(ciphertext), DES.block_size)  # Decrypt and remove padding.


def time_aes_modes(messages, key):  # Compare AES ECB/CBC/CFB/OFB/CTR execution time for several messages.
    modes = ["ECB", "CBC", "CFB", "OFB", "CTR"]  # Define the operation modes requested by the manual pattern.
    results = {}  # Store total time for each mode.
    for mode in modes:  # Test one mode at a time.
        start = time.perf_counter()  # Start timer immediately before encrypting the message set.
        for message in messages:  # Encrypt every supplied message using the same key.
            data = message.encode() if isinstance(message, str) else message  # Convert text input to bytes.
            if mode == "ECB":  # Handle ECB mode.
                cipher = AES.new(key, AES.MODE_ECB)  # Create AES-ECB cipher.
                cipher.encrypt(pad(data, AES.block_size))  # Pad and encrypt the message.
            elif mode == "CBC":  # Handle CBC mode.
                iv = get_random_bytes(16)  # Generate a fresh 16-byte IV.
                cipher = AES.new(key, AES.MODE_CBC, iv)  # Create AES-CBC cipher.
                cipher.encrypt(pad(data, AES.block_size))  # Pad and encrypt the message.
            elif mode == "CFB":  # Handle CFB mode.
                iv = get_random_bytes(16)  # Generate CFB IV.
                cipher = AES.new(key, AES.MODE_CFB, iv)  # Create AES-CFB cipher.
                cipher.encrypt(data)  # CFB works without block padding.
            elif mode == "OFB":  # Handle OFB mode.
                iv = get_random_bytes(16)  # Generate OFB IV.
                cipher = AES.new(key, AES.MODE_OFB, iv)  # Create AES-OFB cipher.
                cipher.encrypt(data)  # OFB works without block padding.
            else:  # The remaining mode is CTR.
                nonce = get_random_bytes(8)  # Generate an 8-byte nonce.
                cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)  # Create AES-CTR cipher.
                cipher.encrypt(data)  # CTR works without block padding.
        results[mode] = time.perf_counter() - start  # Save total time for this mode.
    return results  # Return mode -> seconds mapping.


def plot_timing(timing, title="Execution Time Comparison"):  # Plot an algorithm/mode timing dictionary.
    import matplotlib.pyplot as plt  # Import plotting library only if this function is actually used.
    names = list(timing.keys())  # Extract labels for horizontal axis.
    values = list(timing.values())  # Extract timing values for vertical axis.
    plt.figure()  # Create a new chart.
    plt.bar(names, values)  # Draw one bar for each technique.
    plt.xlabel("Technique")  # Label the horizontal axis.
    plt.ylabel("Time (seconds)")  # Label the vertical axis.
    plt.title(title)  # Give the graph a descriptive title.
    plt.tight_layout()  # Improve spacing around labels.
    plt.show()  # Display the graph.


def lab2_q3_performance_demo():  # Manual Lab 2 Q3: DES vs AES-256 timing.
    return compare_crypto_time("Performance Testing of Encryption Algorithms")  # Reuse the timing helper on the exact manual message.


def lab2_q5_aes192_key_check():  # Manual Lab 2 Q5: explicitly inspect the printed AES-192 key length.
    printed_key = "FEDCBA9876543210FEDCBA9876543210"  # Use the exact hexadecimal key printed in the manual.
    key_bytes = bytes.fromhex(printed_key)  # Decode the hexadecimal text to raw key bytes.
    return {  # Return the important observation instead of silently changing the source.
        "printed_key_bytes": len(key_bytes),  # The printed key is 16 bytes.
        "required_for_AES_192": 24,  # AES-192 requires 24 bytes.
        "usable_as_printed_for_AES_192": len(key_bytes) == 24,  # This evaluates to False.
        "note": "The manual labels this AES-192 but the printed hex key is only 16 bytes (128 bits). A valid AES-192 hex key must contain 48 hex digits.",  # State the mismatch clearly.
    }  # Finish result.


def lab2_additional_modes_demo():  # Manual additional exercise: five messages, same key, different AES modes, compare time.
    messages = ["Message 1", "Message 2", "Message 3", "Message 4", "Message 5"]  # Prepare five different messages.
    key = bytes.fromhex("00112233445566778899AABBCCDDEEFF")  # Use one fixed 16-byte AES-128 key for all messages.
    return time_aes_modes(messages, key)  # Return mode timing results.


def lab2_additional_des_blocks_demo():  # Manual additional exercise: encrypt/decrypt the two supplied hexadecimal blocks using DES.
    key = bytes.fromhex("A1B2C3D4E5F60708")  # Decode the supplied 8-byte DES key from hexadecimal.
    block1 = bytes.fromhex("54686973206973206120636f6e666964656e7469616c206d657373616765")  # Decode printed Block 1.
    block2 = bytes.fromhex("416e64207468697320697320746865207365636f6e6420626c6f636b")  # Decode printed Block 2.
    cipher1 = des_ecb_encrypt(block1, key)  # Encrypt Block 1 using ECB because this exercise does not state a mode.
    cipher2 = des_ecb_encrypt(block2, key)  # Encrypt Block 2 using the same assumption.
    plain1 = des_ecb_decrypt(cipher1, key)  # Decrypt Block 1 to verify.
    plain2 = des_ecb_decrypt(cipher2, key)  # Decrypt Block 2 to verify.
    return {  # Return all values and the implementation assumption.
        "assumed_mode": "ECB because the manual does not specify a mode for this exercise",  # Make our assumption explicit.
        "cipher1_hex": cipher1.hex(),  # Show first ciphertext in readable hexadecimal.
        "cipher2_hex": cipher2.hex(),  # Show second ciphertext in readable hexadecimal.
        "plain1": plain1.decode(),  # Show recovered Block 1 text.
        "plain2": plain2.decode(),  # Show recovered Block 2 text.
    }  # Finish result.

# ---------------------------------------------------------------------------
# LAB 3 — ECC / FIXED-RSA / PERFORMANCE ADDITIONS
# ---------------------------------------------------------------------------

def rsa_textbook_encrypt_charwise(text, n, e):  # Encrypt characters separately for tiny textbook RSA parameters.
    ciphertext = []  # Store one integer ciphertext per character.
    for ch in text:  # Process each plaintext character.
        m = ord(ch)  # Convert the character to its integer code point.
        if m >= n:  # Textbook RSA requires the message integer to be smaller than n.
            raise ValueError(f"Character {ch!r} has value {m}, which is not smaller than n={n}.")  # Stop if the tiny modulus cannot represent it.
        ciphertext.append(pow(m, e, n))  # Compute c=m^e mod n and store it.
    return ciphertext  # Return the integer ciphertext list.


def rsa_textbook_decrypt_charwise(ciphertext, n, d):  # Decrypt character-wise textbook RSA ciphertext.
    plaintext = ""  # Build recovered message here.
    for value in ciphertext:  # Process each encrypted integer.
        m = pow(value, d, n)  # Compute m=c^d mod n.
        plaintext += chr(m)  # Convert recovered integer back to character.
    return plaintext  # Return original text.


def ecc_generate_secp256r1():  # Generate an ECC key pair on the secp256r1 curve.
    from cryptography.hazmat.primitives.asymmetric import ec  # Import elliptic-curve support.
    private_key = ec.generate_private_key(ec.SECP256R1())  # Generate a random private key on secp256r1.
    public_key = private_key.public_key()  # Derive the corresponding public key.
    return public_key, private_key  # Return public key first and private key second.


def _ecc_derive_aes_key(shared_secret):  # Turn an ECDH shared secret into a 32-byte AES key.
    from cryptography.hazmat.primitives import hashes  # Import SHA-256 for key derivation.
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # Import HKDF key-derivation function.
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"IS-Lab-ECC")  # Configure a 256-bit derived key.
    return hkdf.derive(shared_secret)  # Derive and return the AES key.


def ecc_hybrid_encrypt(data, recipient_public_key):  # Practical ECC encryption: ephemeral ECDH + AES-GCM.
    from cryptography.hazmat.primitives.asymmetric import ec  # Import elliptic-curve operations.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # Import authenticated AES-GCM.
    from cryptography.hazmat.primitives import serialization  # Import key serialization helpers.
    import os  # Import secure operating-system random bytes.
    if isinstance(data, str):  # Allow ordinary text input.
        data = data.encode()  # Convert text to bytes.
    ephemeral_private = ec.generate_private_key(ec.SECP256R1())  # Generate a fresh sender-side ephemeral private key.
    shared_secret = ephemeral_private.exchange(ec.ECDH(), recipient_public_key)  # Compute ECDH secret using recipient public key.
    aes_key = _ecc_derive_aes_key(shared_secret)  # Derive an AES-256 key from the shared secret.
    nonce = os.urandom(12)  # Generate a standard 12-byte GCM nonce.
    ciphertext = AESGCM(aes_key).encrypt(nonce, data, None)  # Encrypt and authenticate the plaintext.
    ephemeral_public_pem = ephemeral_private.public_key().public_bytes(  # Serialize the sender's ephemeral public key.
        encoding=serialization.Encoding.PEM,  # Use PEM encoding for easy storage/transmission.
        format=serialization.PublicFormat.SubjectPublicKeyInfo,  # Use standard public-key container format.
    )  # Finish serialization call.
    return {"ephemeral_public": ephemeral_public_pem, "nonce": nonce, "ciphertext": ciphertext}  # Return everything receiver needs.


def ecc_hybrid_decrypt(package, recipient_private_key):  # Decrypt a package produced by ecc_hybrid_encrypt().
    from cryptography.hazmat.primitives.asymmetric import ec  # Import ECDH operation.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # Import AES-GCM decryption.
    from cryptography.hazmat.primitives import serialization  # Import PEM public-key loader.
    ephemeral_public = serialization.load_pem_public_key(package["ephemeral_public"])  # Load sender's ephemeral public key.
    shared_secret = recipient_private_key.exchange(ec.ECDH(), ephemeral_public)  # Recompute identical ECDH shared secret.
    aes_key = _ecc_derive_aes_key(shared_secret)  # Derive the same AES-256 key.
    return AESGCM(aes_key).decrypt(package["nonce"], package["ciphertext"], None)  # Authenticate and recover plaintext.


def rsa_hybrid_encrypt(data, public_key):  # Encrypt large data with AES and protect only the AES key using RSA.
    if isinstance(data, str):  # Allow normal text input.
        data = data.encode()  # Convert text to bytes.
    aes_key = get_random_bytes(32)  # Generate a random 32-byte AES-256 session key.
    ciphertext, iv = aes_cbc_encrypt(data, aes_key)  # Encrypt the large data efficiently with AES.
    encrypted_key = rsa_encrypt_bytes(aes_key, public_key)  # Encrypt the small AES key using RSA public key.
    return {"ciphertext": ciphertext, "iv": iv, "encrypted_key": encrypted_key}  # Return hybrid package.


def rsa_hybrid_decrypt(package, private_key):  # Reverse RSA-hybrid encryption.
    aes_key = rsa_decrypt_bytes(package["encrypted_key"], private_key)  # Recover the AES key using RSA private key.
    return aes_cbc_decrypt(package["ciphertext"], aes_key, package["iv"])  # Decrypt the actual data using AES.


def lab3_ecc_demo():  # Manual Lab 3 Q2: encrypt/decrypt "Secure Transactions" using the curve-based hybrid pattern.
    public_key, private_key = ecc_generate_secp256r1()  # Generate secp256r1 recipient key pair.
    package = ecc_hybrid_encrypt("Secure Transactions", public_key)  # Encrypt the message using recipient public key through ECDH+AES.
    plaintext = ecc_hybrid_decrypt(package, private_key).decode()  # Decrypt using recipient private key.
    return {  # Return display values.
        "ciphertext_hex": package["ciphertext"].hex(),  # Show encrypted message bytes.
        "decrypted": plaintext,  # Show recovered text.
        "note": "ECC is normally used for key agreement; this implementation uses secp256r1 ECDH to derive an AES-GCM key.",  # Explain the practical pattern.
    }  # Finish result.


def compare_rsa_ecc_file_transfer(sizes=(1_000_000, 10_000_000)):  # Compare RSA-2048 hybrid and secp256r1 hybrid file transfer.
    import os  # Import random-file-byte generator.
    rows = []  # Store one performance row per requested file size.
    for size in sizes:  # Test each file size independently.
        data = os.urandom(size)  # Generate sample file contents of exactly this many bytes.
        start = time.perf_counter()  # Start RSA key-generation timer.
        rsa_public, rsa_private = rsa_generate(2048)  # Generate RSA-2048 pair.
        rsa_keygen = time.perf_counter() - start  # Store RSA key generation time.
        start = time.perf_counter()  # Start RSA-hybrid encryption timer.
        rsa_package = rsa_hybrid_encrypt(data, rsa_public)  # Encrypt file using AES and RSA-wrapped AES key.
        rsa_encrypt_time = time.perf_counter() - start  # Store RSA-hybrid encryption time.
        start = time.perf_counter()  # Start RSA-hybrid decryption timer.
        rsa_recovered = rsa_hybrid_decrypt(rsa_package, rsa_private)  # Decrypt file.
        rsa_decrypt_time = time.perf_counter() - start  # Store RSA-hybrid decryption time.
        start = time.perf_counter()  # Start ECC key-generation timer.
        ecc_public, ecc_private = ecc_generate_secp256r1()  # Generate secp256r1 pair.
        ecc_keygen = time.perf_counter() - start  # Store ECC key generation time.
        start = time.perf_counter()  # Start ECC-hybrid encryption timer.
        ecc_package = ecc_hybrid_encrypt(data, ecc_public)  # Encrypt file with ECDH-derived AES-GCM key.
        ecc_encrypt_time = time.perf_counter() - start  # Store ECC-hybrid encryption time.
        start = time.perf_counter()  # Start ECC-hybrid decryption timer.
        ecc_recovered = ecc_hybrid_decrypt(ecc_package, ecc_private)  # Decrypt file.
        ecc_decrypt_time = time.perf_counter() - start  # Store ECC-hybrid decryption time.
        rows.append({  # Save all performance metrics for this file size.
            "size_bytes": size,  # Record tested file size.
            "rsa_keygen_s": rsa_keygen,  # RSA key-generation time.
            "rsa_encrypt_s": rsa_encrypt_time,  # RSA-hybrid encryption time.
            "rsa_decrypt_s": rsa_decrypt_time,  # RSA-hybrid decryption time.
            "rsa_correct": rsa_recovered == data,  # Verify recovered RSA-hybrid file.
            "ecc_keygen_s": ecc_keygen,  # ECC key-generation time.
            "ecc_encrypt_s": ecc_encrypt_time,  # ECC-hybrid encryption time.
            "ecc_decrypt_s": ecc_decrypt_time,  # ECC-hybrid decryption time.
            "ecc_correct": ecc_recovered == data,  # Verify recovered ECC-hybrid file.
        })  # Finish this result row.
    return rows  # Return the complete performance report.


def lab3_rsa_ecc_file_transfer_demo():  # Manual Lab 3 Q4: run 1 MB and 10 MB RSA/ECC comparison.
    return compare_rsa_ecc_file_transfer((1_000_000, 10_000_000))  # Execute the two requested file sizes.


def lab3_fixed_rsa_demo():  # Manual additional Q3: n=323,e=5,d=173 on "Cryptographic Protocols".
    n = 323  # Use the supplied RSA modulus.
    e = 5  # Use the supplied public exponent.
    d = 173  # Use the supplied private exponent.
    ciphertext = rsa_textbook_encrypt_charwise("Cryptographic Protocols", n, e)  # Encrypt each character with the supplied public key.
    plaintext = rsa_textbook_decrypt_charwise(ciphertext, n, d)  # Decrypt each integer with the supplied private key.
    return ciphertext, plaintext  # Return both encrypted list and recovered message.


def lab3_healthcare_curve_demo():  # Manual additional healthcare question that mentions secp256r1.
    public_key, private_key = ecc_generate_secp256r1()  # Generate the explicitly named secp256r1 key pair.
    record = "Patient Name: Riya | Diagnosis: Example"  # Create sample medical record.
    start = time.perf_counter()  # Start encryption timer.
    package = ecc_hybrid_encrypt(record, public_key)  # Encrypt record using secp256r1 ECDH + AES-GCM.
    encryption_time = time.perf_counter() - start  # Save encryption time.
    start = time.perf_counter()  # Start decryption timer.
    plaintext = ecc_hybrid_decrypt(package, private_key).decode()  # Recover patient record.
    decryption_time = time.perf_counter() - start  # Save decryption time.
    return {  # Return result and important wording note.
        "decrypted": plaintext,  # Show recovered record.
        "encryption_s": encryption_time,  # Show encryption time.
        "decryption_s": decryption_time,  # Show decryption time.
        "note": "The manual wording mixes ElGamal with secp256r1. secp256r1 is an elliptic curve, so this function implements the explicitly curve-based part.",  # Do not silently merge two different schemes.
    }  # Finish result.


# ---------------------------------------------------------------------------
# LAB 4 — KEY MANAGEMENT / RSA ATTACK ADDITIONS
# ---------------------------------------------------------------------------

def rabin_generate(bits=1024):  # Generate a configurable Rabin key pair with p,q congruent to 3 mod 4.
    from Crypto.Util.number import getPrime  # Import secure prime generation from PyCryptodome.
    half = bits // 2  # Each prime should be roughly half the modulus size.
    while True:  # Keep generating until p satisfies Rabin's convenient condition.
        p = getPrime(half)  # Generate a random prime.
        if p % 4 == 3:  # Check p=3 mod 4.
            break  # Accept p.
    while True:  # Generate q separately.
        q = getPrime(half)  # Generate another random prime.
        if q % 4 == 3 and q != p:  # Require q=3 mod 4 and distinct from p.
            break  # Accept q.
    return p * q, (p, q)  # Public key is n=pq; private key is (p,q).


class RabinKeyManager:  # Centralized Rabin key-management service for hospitals/clinics.
    def __init__(self, bits=1024):  # Initialize service with configurable key size.
        self.bits = bits  # Remember desired modulus size.
        self.records = {}  # Store facility -> key information.
        self.revoked = set()  # Track facilities whose keys are revoked.
        self.logs = []  # Store audit history.

    def generate(self, facility):  # Generate a fresh Rabin pair for one facility.
        public_n, private_pq = rabin_generate(self.bits)  # Create public and private Rabin keys.
        self.records[facility] = {"public": public_n, "private": private_pq, "created": timestamp_now()}  # Store key record internally.
        self.revoked.discard(facility)  # A newly generated key is active.
        audit_log(self.logs, "Rabin key generation", facility, "SUCCESS")  # Record key-generation event.
        return public_n  # Return only the shareable public key by default.

    def distribute_public(self, facility):  # Return active public key.
        if facility in self.revoked:  # Check whether this facility is revoked.
            raise PermissionError("Facility key is revoked.")  # Block distribution of revoked key.
        audit_log(self.logs, "Public key distribution", facility, "SUCCESS")  # Log the action.
        return self.records[facility]["public"]  # Return public modulus.

    def distribute_private(self, facility, authorized=False):  # Return private key only after explicit authorization.
        if not authorized:  # Check permission flag.
            audit_log(self.logs, "Private key request", facility, "DENIED")  # Log denied access.
            raise PermissionError("Private key access denied.")  # Protect private key.
        if facility in self.revoked:  # Reject revoked facility.
            raise PermissionError("Facility key is revoked.")  # Stop use of revoked private key.
        audit_log(self.logs, "Private key distribution", facility, "SUCCESS")  # Log successful access.
        return self.records[facility]["private"]  # Return (p,q) only to authorized caller.

    def revoke(self, facility):  # Revoke a facility's current key.
        self.revoked.add(facility)  # Mark facility revoked.
        audit_log(self.logs, "Rabin key revocation", facility, "SUCCESS")  # Record revocation.

    def renew(self, facility):  # Replace a facility's key with a fresh pair.
        audit_log(self.logs, "Rabin key renewal", facility, "STARTED")  # Log renewal request.
        return self.generate(facility)  # Generate and activate a new pair.

    def renew_all(self):  # Renew every currently registered facility.
        for facility in list(self.records.keys()):  # Work on a snapshot of facility names.
            self.renew(facility)  # Generate fresh keys for that facility.


class ElGamalAccessManager:  # Simple DRM-style ElGamal key and access-control service.
    def __init__(self, p=7919, g=2):  # Create manager with master ElGamal pair.
        self.public_key, self.private_key = elgamal_generate(p, g)  # Generate master public/private values.
        self.content = {}  # Store encrypted content by ID.
        self.permissions = {}  # Store customer -> set of allowed content IDs.
        self.logs = []  # Store audit events.

    def encrypt_content(self, content_id, text):  # Encrypt uploaded content using master public key.
        self.content[content_id] = elgamal_encrypt_text(text, self.public_key)  # Encrypt and save content.
        audit_log(self.logs, f"Encrypt {content_id}", "creator", "SUCCESS")  # Log content encryption.

    def grant(self, customer, content_id):  # Grant one customer access to one item.
        self.permissions.setdefault(customer, set()).add(content_id)  # Add content ID to customer's access set.
        audit_log(self.logs, f"Grant {content_id}", customer, "SUCCESS")  # Log grant.

    def revoke(self, customer, content_id):  # Revoke one access permission.
        self.permissions.setdefault(customer, set()).discard(content_id)  # Remove the content ID if present.
        audit_log(self.logs, f"Revoke {content_id}", customer, "SUCCESS")  # Log revocation.

    def decrypt_for_customer(self, customer, content_id):  # Decrypt only when customer currently has access.
        if content_id not in self.permissions.get(customer, set()):  # Check access-control list.
            audit_log(self.logs, f"Decrypt {content_id}", customer, "DENIED")  # Log denied attempt.
            raise PermissionError("Customer does not have access to this content.")  # Block unauthorized decryption.
        plaintext = elgamal_decrypt_text(self.content[content_id], self.public_key[0], self.private_key)  # Decrypt authorized content.
        audit_log(self.logs, f"Decrypt {content_id}", customer, "SUCCESS")  # Log successful decryption.
        return plaintext  # Return content to authorized customer.


def factor_small_rsa_modulus(n):  # Factor a deliberately weak/small RSA modulus by trial division.
    limit = math.isqrt(n) + 1  # Any non-trivial small factor must appear at or below sqrt(n).
    for candidate in range(2, limit):  # Try each possible factor.
        if n % candidate == 0:  # Check whether candidate divides n exactly.
            return candidate, n // candidate  # Return recovered prime factors.
    return None  # Report failure if no small factor was found.


def recover_weak_rsa_private_key(n, e):  # Reconstruct private exponent after factoring weak RSA modulus.
    factors = factor_small_rsa_modulus(n)  # Attempt to recover p and q.
    if factors is None:  # Check attack result.
        raise ValueError("No small factor found using this simple demonstration attack.")  # Stop if trial division failed.
    p, q = factors  # Unpack recovered factors.
    phi = (p - 1) * (q - 1)  # Compute Euler's totient.
    d = pow(e, -1, phi)  # Recover private exponent as inverse of e modulo phi.
    return {"p": p, "q": q, "phi": phi, "d": d}  # Return reconstructed private-key components.

# ---------------------------------------------------------------------------
# LAB 4 — COMPLETE MANUAL DEMOS
# ---------------------------------------------------------------------------

def lab4_healthcare_rabin_manager_demo():  # Manual Lab 4 Q2: centralized Rabin key-management service.
    manager = RabinKeyManager(bits=1024)  # Create a 1024-bit configurable Rabin manager.
    manager.generate("Hospital-A")  # Generate a key pair for the first hospital.
    manager.generate("Clinic-B")  # Generate a key pair for the clinic.
    public_n = manager.distribute_public("Hospital-A")  # Obtain Hospital-A public key.
    private_pq = manager.distribute_private("Hospital-A", authorized=True)  # Obtain private key through an authorized path.
    message_integer = 12345  # Use a small integer as sample encoded patient data.
    ciphertext = rabin_encrypt_int(message_integer, public_n)  # Encrypt sample data with Rabin public modulus.
    roots = rabin_decrypt_roots(ciphertext, private_pq)  # Recover the four Rabin plaintext candidates.
    manager.revoke("Clinic-B")  # Demonstrate key revocation.
    manager.renew("Hospital-A")  # Demonstrate key renewal.
    return {  # Return all useful lab outputs.
        "ciphertext": ciphertext,  # Show encrypted integer.
        "roots": roots,  # Show four Rabin roots.
        "original_is_one_root": message_integer in roots,  # Verify original appears among candidates.
        "logs": manager.logs,  # Show audit history.
        "compliance_note": "HIPAA/regulatory compliance also requires organizational policies, access controls, audit procedures and secure deployment beyond this classroom code.",  # Keep the compliance statement accurate.
    }  # Finish result.


def lab4_digirights_elgamal_demo():  # Manual Lab 4 additional Q1: ElGamal DRM key management + access control.
    manager = ElGamalAccessManager()  # Create master ElGamal manager.
    manager.encrypt_content("ebook-1", "Protected digital content")  # Encrypt uploaded content.
    manager.grant("customer-A", "ebook-1")  # Grant the customer access.
    allowed_plaintext = manager.decrypt_for_customer("customer-A", "ebook-1")  # Demonstrate authorized decryption.
    manager.revoke("customer-A", "ebook-1")  # Revoke access to the same content.
    denied = False  # Track whether the post-revocation attempt is correctly blocked.
    try:  # Attempt decryption after revocation.
        manager.decrypt_for_customer("customer-A", "ebook-1")  # This should raise PermissionError.
    except PermissionError:  # Catch the expected access denial.
        denied = True  # Record that revocation worked.
    return {"authorized_plaintext": allowed_plaintext, "revocation_blocks_access": denied, "logs": manager.logs}  # Return DRM demonstration results.


def lab4_weak_rsa_attack_demo():  # Manual Lab 4 additional Q2: demonstrate attack on vulnerable RSA key generation.
    n = 323  # Use a deliberately tiny factorable modulus for the classroom attack.
    e = 5  # Use a public exponent compatible with the tiny example.
    recovered = recover_weak_rsa_private_key(n, e)  # Factor n and recover d.
    recovered["mitigation"] = "Use large independent random primes, secure RNG, modern RSA key sizes, standard key-generation libraries, and protect/rotate private keys."  # Add mitigation summary.
    return recovered  # Return recovered secret components and mitigation note.


# ---------------------------------------------------------------------------
# LAB 5 — MULTIPART CLIENT/SERVER ADDITIONAL EXERCISE
# ---------------------------------------------------------------------------

def multipart_hash_server(host="127.0.0.1", port=5002):  # Server reassembles multiple message parts and returns one SHA-256 hash.
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP server socket.
    server.bind((host, port))  # Bind it to the chosen host and port.
    server.listen(1)  # Wait for one client connection.
    print("Multipart hash server waiting...")  # Display server status.
    connection, address = server.accept()  # Accept the client.
    data = b""  # Store all message bytes received so far.
    while True:  # Receive chunks until the end marker appears.
        chunk = connection.recv(4096)  # Receive the next network chunk.
        if not chunk:  # Empty bytes mean the connection ended.
            break  # Stop reading.
        if b"<END>" in chunk:  # Check whether the client marked the end of the message.
            data += chunk.replace(b"<END>", b"")  # Add final bytes but remove the marker itself.
            break  # The complete message has now been reassembled.
        data += chunk  # Append this ordinary chunk to the message.
    digest = sha256_hex(data)  # Hash the fully reassembled message.
    connection.sendall(digest.encode())  # Send the server-side hash back to the client.
    connection.close()  # Close the client connection.
    server.close()  # Close the listening socket.


def multipart_hash_client(parts, host="127.0.0.1", port=5002):  # Client sends a message in separate parts and verifies the server hash.
    original_message = "".join(parts)  # Reconstruct the complete original message locally for comparison.
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP client socket.
    client.connect((host, port))  # Connect to the multipart server.
    for part in parts:  # Send every supplied part separately.
        client.sendall(part.encode())  # Transmit one part.
    client.sendall(b"<END>")  # Send a marker so server knows the message is complete.
    server_hash = client.recv(4096).decode()  # Receive SHA-256 of server's reassembled message.
    local_hash = sha256_hex(original_message)  # Hash the original complete message locally.
    client.close()  # Close client connection.
    return {"server_hash": server_hash, "local_hash": local_hash, "integrity_ok": server_hash == local_hash}  # Return verification result.


# ---------------------------------------------------------------------------
# LAB 6 — ELGAMAL SIGNATURE + COMPLETE MANUAL DEMOS
# ---------------------------------------------------------------------------

def elgamal_sign(message, p, g, private_x):  # Create a textbook ElGamal digital signature for a message.
    digest = int.from_bytes(hashlib.sha256(message.encode()).digest(), "big") % (p - 1)  # Hash the message into the exponent range.
    while True:  # Keep choosing a signing nonce until it is invertible modulo p-1.
        k = random.randint(2, p - 2)  # Choose random temporary signing value.
        if math.gcd(k, p - 1) == 1:  # Check that k has a modular inverse.
            break  # Accept this nonce.
    r = pow(g, k, p)  # Compute the first signature component.
    k_inverse = pow(k, -1, p - 1)  # Compute inverse of k modulo p-1.
    s = ((digest - private_x * r) * k_inverse) % (p - 1)  # Compute second signature component.
    return r, s  # Return the ElGamal signature pair.


def elgamal_verify(message, signature, public_key):  # Verify a textbook ElGamal digital signature.
    p, g, y = public_key  # Unpack sender public key.
    r, s = signature  # Unpack signature components.
    if not (0 < r < p):  # Check that r is inside valid range.
        return False  # Immediately reject an invalid signature structure.
    digest = int.from_bytes(hashlib.sha256(message.encode()).digest(), "big") % (p - 1)  # Recompute message hash.
    left = pow(g, digest, p)  # Compute g^H(m) mod p.
    right = (pow(y, r, p) * pow(r, s, p)) % p  # Compute y^r * r^s mod p.
    return left == right  # Signature is valid only when both sides match.


def lab6_elgamal_signature_demo():  # Manual Lab 6 Q1 part: try ElGamal signing and verification.
    public_key, private_x = elgamal_generate()  # Generate ElGamal key pair.
    message = "Alice legal document"  # Use a sample electronic document.
    signature = elgamal_sign(message, public_key[0], public_key[1], private_x)  # Sign using private key.
    valid = elgamal_verify(message, signature, public_key)  # Verify using public key.
    return {"public_key": public_key, "signature": signature, "valid": valid}  # Return signing result.


def lab6_diffie_hellman_demo():  # Manual Lab 6 Q2: demonstrate the Diffie-Hellman operation that actually applies.
    result = dh_demo(7919, 2)  # Generate Alice/Bob values and shared secret.
    result["note"] = "Diffie-Hellman is a key-exchange mechanism, not a standalone digital-signature algorithm."  # Clarify the manual wording.
    return result  # Return DH values and explanation.


def cia_triad_rsa_signature_hash_demo(message="Highly confidential information"):  # Manual Lab 6 additional: CIA using RSA + SHA + signature.
    public_key, private_key = rsa_generate(2048)  # Generate RSA pair.
    encrypted_chunks = rsa_encrypt_long_message(message, public_key)  # CONFIDENTIALITY: encrypt with public key.
    encrypted_blob = b"".join(encrypted_chunks)  # Join encrypted chunks for hashing and signing.
    stored_hash = sha256_hex(encrypted_blob)  # INTEGRITY: hash the encrypted data.
    signature = rsa_sign_sha256(encrypted_blob, private_key)  # AUTHENTICITY: sign using private key.
    integrity_ok, current_hash = integrity_check(encrypted_blob, stored_hash)  # Receiver recomputes and compares hash.
    signature_ok = rsa_verify_sha256(encrypted_blob, signature, public_key)  # Receiver verifies signature with public key.
    plaintext = None  # Do not expose plaintext before verification succeeds.
    if integrity_ok and signature_ok:  # Require both integrity and authenticity.
        plaintext = rsa_decrypt_long_message(encrypted_chunks, private_key).decode()  # Decrypt only after successful checks.
    return {  # Return CIA demonstration information.
        "ciphertext_hex": encrypted_blob.hex(),  # Confidential encrypted representation.
        "stored_hash": stored_hash,  # Sender-side integrity digest.
        "recomputed_hash": current_hash,  # Receiver-side digest.
        "signature_hex": signature.hex(),  # Digital signature.
        "integrity_ok": integrity_ok,  # Integrity verification status.
        "signature_ok": signature_ok,  # Authenticity verification status.
        "plaintext": plaintext,  # Original data visible only after checks.
    }  # Finish result.



# ============================================================================
# LAB 7 — PAILLIER ADDITION + ELGAMAL/RSA TEXTBOOK MULTIPLICATION
# ============================================================================

import secrets  # Use cryptographically secure random integers for new functions.
import hmac  # Build keyed, deterministic exact-match search tokens.
import re  # Tokenize searchable words.
import json  # Serialize records without relying on dictionary insertion order.
from Crypto.Util.number import getPrime  # Generate independent Paillier primes.
from Crypto.Hash import MD5, SHA512  # Match the hash named explicitly in a question.


def paillier_keygen(bits=1024):  # Generate genuine additive Paillier keys; default is 1024-bit lab size.
    if bits < 512 or bits % 2:  # Reject inappropriate modulus sizes and odd bit counts.
        raise ValueError("Use an even Paillier modulus size of at least 512 bits.")  # Explain invalid input.
    p = getPrime(bits // 2)  # Generate the first random prime.
    q = getPrime(bits // 2)  # Generate the second random prime.
    while q == p:  # Never reuse the same prime.
        q = getPrime(bits // 2)  # Regenerate if necessary.
    n = p * q  # Compute the public modulus.
    lam = math.lcm(p - 1, q - 1)  # Compute the private Carmichael value.
    g = n + 1  # Choose the standard Paillier generator.
    n2 = n * n  # Cache the ciphertext modulus.
    l_value = (pow(g, lam, n2) - 1) // n  # Evaluate the L function.
    mu = pow(l_value, -1, n)  # Precompute the private decryption inverse.
    return {"n": n, "g": g}, {"lambda": lam, "mu": mu}  # Return serializable key dictionaries.


def paillier_encrypt(amount, public):  # Encrypt one nonnegative integer with fresh randomness.
    n = int(public["n"])  # Read the Paillier modulus.
    if not isinstance(amount, int) or not 0 <= amount < n:  # Require one value in the plaintext space.
        raise ValueError("Paillier plaintext must be an integer from 0 to n-1.")  # Prevent silent wrapping.
    r = secrets.randbelow(n - 1) + 1  # Sample fresh random r.
    while math.gcd(r, n) != 1:  # Encryption requires r invertible modulo n.
        r = secrets.randbelow(n - 1) + 1  # Draw again if r shares a factor with n.
    return (pow(int(public["g"]), amount, n * n) * pow(r, n, n * n)) % (n * n)  # Encrypt modulo n squared.


def paillier_add(ciphertexts, public):  # Add encrypted amounts without decrypting any of them.
    n2 = int(public["n"]) ** 2  # Compute ciphertext modulus.
    result = 1  # Encryption of zero is the multiplicative identity.
    for item in ciphertexts:  # Visit every selected encrypted amount.
        c = int(item)  # Accept stored JSON decimal strings as well as integers.
        if not 0 < c < n2 or math.gcd(c, n2) != 1:  # Reject malformed ciphertext.
            raise ValueError("Invalid Paillier ciphertext.")  # Avoid silently accepting corruption.
        result = result * c % n2  # Ciphertext multiplication means plaintext addition.
    return result  # This result stays encrypted until the final decrypt.


def paillier_scalar(ciphertext, factor, public):  # Multiply a plaintext by a public integer constant.
    if factor < 0:  # This short version supports nonnegative factors.
        raise ValueError("Factor must be nonnegative.")  # Reject unsupported signed arithmetic.
    return pow(int(ciphertext), factor, int(public["n"]) ** 2)  # E(m)^k = E(k*m).


def paillier_decrypt(ciphertext, public, private):  # Decrypt one ciphertext, preferably only the aggregate.
    n = int(public["n"])  # Read modulus.
    c = int(ciphertext)  # Convert serialized ciphertext.
    if not 0 < c < n * n or math.gcd(c, n * n) != 1:  # Check ciphertext group membership.
        raise ValueError("Invalid Paillier ciphertext.")  # Handle altered storage cleanly.
    l_value = (pow(c, int(private["lambda"]), n * n) - 1) // n  # Evaluate L(c^lambda).
    return l_value * int(private["mu"]) % n  # Recover the sum modulo n.


def elgamal_multiply_ciphertexts(first, second, p):  # Homomorphic product for textbook ElGamal pairs.
    return ((first[0] * second[0]) % p, (first[1] * second[1]) % p)  # Multiply each component modulo p.


def rsa_textbook_multiply(c1, c2, n):  # Demonstrate multiplicative textbook RSA only.
    return c1 * c2 % n  # OAEP-padded RSA does not have this property.


def lab7_paillier_demo():  # Show lab-7 addition without individual decryption.
    public, private = paillier_keygen(512)  # Generate a fast demonstration key.
    first = paillier_encrypt(15, public)  # Encrypt first lab example.
    second = paillier_encrypt(25, public)  # Encrypt second lab example.
    combined = paillier_add([first, second], public)  # Add while encrypted.
    return {"E(15)": first, "E(25)": second, "E(15+25)": combined,
            "decrypted_final_sum": paillier_decrypt(combined, public, private)}  # Check result 40.


# ============================================================================
# LAB 8 — KEYED EXACT SEARCH INDEX AND ENCRYPTED DOCUMENTS
# ============================================================================


def search_token(value, index_key):  # Make an exact-match blind index for a field/word.
    if not isinstance(index_key, bytes) or len(index_key) < 16:  # Require a secret index key.
        raise ValueError("Index key must contain at least 16 bytes.")  # Reject weak key input.
    normalized = " ".join(str(value).casefold().split())  # Normalize case and whitespace consistently.
    return hmac.new(index_key, normalized.encode(), hashlib.sha256).hexdigest()  # Return stable keyed token.


def searchable_encrypt_document(doc_id, text, aes_key, index_key):  # Encrypt text and index its words.
    words = sorted(set(re.findall(r"[\w]+", text.casefold())))  # Extract unique searchable words.
    nonce = get_random_bytes(12)  # Generate a fresh AES-GCM nonce.
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)  # Use authenticated encryption.
    cipher.update(str(doc_id).encode())  # Bind ciphertext to its public document ID.
    encrypted, tag = cipher.encrypt_and_digest(text.encode())  # Encrypt and authenticate contents.
    return {"id": str(doc_id), "nonce": nonce.hex(), "ciphertext": encrypted.hex(),
            "tag": tag.hex(), "tokens": [search_token(w, index_key) for w in words]}  # Store searchable tokens.


def searchable_find(documents, query, index_key):  # Match tokens without decrypting document contents.
    token = search_token(query, index_key)  # Derive query token from the shared secret.
    return [d for d in documents if token in d["tokens"]]  # Return matching encrypted records.


def searchable_decrypt_document(record, aes_key):  # Decrypt a matching record when authorized.
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=bytes.fromhex(record["nonce"]))  # Restore AES nonce.
    cipher.update(str(record["id"]).encode())  # Supply the same authenticated ID.
    raw = cipher.decrypt_and_verify(bytes.fromhex(record["ciphertext"]), bytes.fromhex(record["tag"]))  # Detect tampering.
    return raw.decode()  # Return UTF-8 plaintext.


def searchable_exact_index(records, field, index_key):  # Index a structured field such as Grant ID.
    return {search_token(row[field], index_key): row for row in records}  # Lookups reveal matching IDs/access patterns.


def canonical_bytes(record):  # Serialize the same fields identically for hashing and verification.
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()  # Stable UTF-8.


def rsa_sign_md5(data, private_key):  # Match an exam requirement to sign an MD5 digest.
    return pkcs1_15.new(private_key).sign(MD5.new(data))  # PKCS#1 v1.5 signature over MD5(data).


def rsa_verify_md5(data, signature, public_key):  # Verify the named hash and RSA signature.
    try:  # Invalid signatures raise ValueError or TypeError.
        pkcs1_15.new(public_key).verify(MD5.new(data), signature)  # Recompute digest and verify.
        return True  # Return success without decrypting data.
    except (ValueError, TypeError):  # Treat changed data as failed verification.
        return False  # Never accept altered data.


def rsa_sign_sha512(data, private_key):  # Sign a SHA-512 digest when specifically requested.
    return pkcs1_15.new(private_key).sign(SHA512.new(data))  # Sign SHA-512 hash of bytes.


def rsa_verify_sha512(data, signature, public_key):  # Check RSA signature with SHA-512.
    try:  # Catch invalid data or signature.
        pkcs1_15.new(public_key).verify(SHA512.new(data), signature)  # Verify same bytes.
        return True  # Signature valid.
    except (ValueError, TypeError):  # Handle tampering.
        return False  # Signature invalid.


def elgamal_sign_digest(digest_bytes, p, g, x):  # Sign already-hashed ballot bytes using textbook ElGamal.
    h = int.from_bytes(digest_bytes, "big") % (p - 1)  # Fit the digest into the exponent group.
    k = secrets.randbelow(p - 3) + 2  # Choose a fresh unpredictable signing nonce.
    while math.gcd(k, p - 1) != 1:  # Inverse exists only for coprime nonce.
        k = secrets.randbelow(p - 3) + 2  # Regenerate rather than reusing a nonce.
    r = pow(g, k, p)  # Compute first signature component.
    s = ((h - x * r) * pow(k, -1, p - 1)) % (p - 1)  # Compute second component.
    return (r, s)  # Keep both components as integers.


def elgamal_verify_digest(digest_bytes, signature, p, g, y):  # Verify textbook ElGamal hash signature.
    r, s = map(int, signature)  # Read serialized integer components.
    if not (1 <= r < p and 0 <= s < p - 1):  # Reject invalid format.
        return False  # Stop on malformed signature.
    h = int.from_bytes(digest_bytes, "big") % (p - 1)  # Recreate signed integer.
    return pow(g, h, p) == (pow(y, r, p) * pow(r, s, p)) % p  # Check signature equation.


def lab8_search_demo():  # Show search over AES-encrypted documents.
    aes_key, index_key = get_random_bytes(32), get_random_bytes(32)  # Generate independent keys.
    docs = [searchable_encrypt_document(i, text, aes_key, index_key) for i, text in
            enumerate(["grant expense research", "ballot constituency research"], 1)]  # Build small corpus.
    hits = searchable_find(docs, "research", index_key)  # Find by word without decrypting.
    return {"encrypted_ids": [d["id"] for d in hits],
            "authorized_plaintext": [searchable_decrypt_document(d, aes_key) for d in hits]}  # Decrypt after search.


# LAB 8 manual variations: encrypted inverted posting lists and ten-document corpus.
def sse_build_inverted(corpus, aes_key, index_key):  # Build token -> AES-GCM encrypted document IDs.
    posting = {}  # Collect document IDs for each normalized word.
    for doc_id, text in corpus.items():  # Visit all plaintext documents before encrypting them.
        for word in set(re.findall(r"[\w]+", text.casefold())):  # Index each distinct word once.
            token = search_token("word:" + word, index_key)  # Hide index word with a keyed token.
            posting.setdefault(token, []).append(str(doc_id))  # Attach document ID to its posting list.
    encrypted = {}  # Save encrypted posting lists, not clear document IDs.
    for token, ids in posting.items():  # Encrypt each posting list separately.
        nonce = get_random_bytes(12)  # Use a fresh nonce for this posting list.
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)  # Create authenticated AES cipher.
        cipher.update(token.encode())  # Bind contents to token so entries cannot be swapped.
        data, tag = cipher.encrypt_and_digest(json.dumps(ids).encode())  # Encrypt all matching IDs.
        encrypted[token] = {"nonce": nonce.hex(), "data": data.hex(), "tag": tag.hex()}  # Keep JSON-safe form.
    return encrypted  # Server sees tokens, encrypted ID lists, and access patterns.


def sse_search_inverted(encrypted_index, query, aes_key, index_key):  # Retrieve IDs by encrypted word index.
    token = search_token("word:" + query.casefold().strip(), index_key)  # Create query trapdoor.
    entry = encrypted_index.get(token)  # Locate posting list without reading other terms.
    if entry is None:  # Missing word has no matching documents.
        return []  # Return empty ID list.
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=bytes.fromhex(entry["nonce"]))  # Restore cipher.
    cipher.update(token.encode())  # Authenticate which token is being queried.
    ids = cipher.decrypt_and_verify(bytes.fromhex(entry["data"]), bytes.fromhex(entry["tag"]))  # Verify/decrypt IDs.
    return json.loads(ids)  # Return IDs to an authorized client.


def lab8_ten_document_demo():  # Run the lab manual's ten-document SSE exercise.
    corpus = {str(i): f"Document {i} discusses {topic} and secure records" for i, topic in enumerate(
        ["grant", "vote", "health", "bank", "research", "grant", "vote", "audit", "finance", "search"], 1)}  # Ten texts.
    aes_key, index_key = get_random_bytes(32), get_random_bytes(32)  # Independent encryption/index keys.
    index = sse_build_inverted(corpus, aes_key, index_key)  # Encrypt the inverted index.
    documents = [searchable_encrypt_document(i, text, aes_key, index_key) for i, text in corpus.items()]  # Encrypt documents.
    ids = sse_search_inverted(index, "grant", aes_key, index_key)  # Query encrypted index.
    recovered = [searchable_decrypt_document(d, aes_key) for d in documents if d["id"] in ids]  # Open matching docs.
    return {"encrypted_index_size": len(index), "matching_ids": ids, "matching_texts": recovered}  # Show all outputs.


def lab8_paillier_postings_demo():  # Partial PKSE-like demo: encrypt ID list values with Paillier.
    public, private = paillier_keygen(512)  # Generate Paillier key pair.
    secret = get_random_bytes(32)  # A separate search token key remains necessary.
    corpus = {"1": "secure grant", "2": "secure vote", "3": "grant research"}  # Small sample.
    encrypted_index = {}  # Store encrypted numeric document IDs.
    for doc_id, text in corpus.items():  # Scan plaintext at index-building time.
        for word in set(text.split()):  # Process each word once per document.
            token = search_token("word:" + word, secret)  # Use a deterministic keyed lookup token.
            encrypted_index.setdefault(token, []).append(paillier_encrypt(int(doc_id), public))  # Encrypt ID.
    token = search_token("word:grant", secret)  # Form an authorized exact query token.
    found = [paillier_decrypt(c, public, private) for c in encrypted_index.get(token, [])]  # Recover matching IDs.
    return {"encrypted_index": encrypted_index, "query_token": token, "matching_ids": found}  # Demonstrate result.


# ============================================================================
# COMPLETE ROLE-BASED SCENARIO FUNCTIONS — SEARCH GRANT OR VOTING
# ============================================================================

from datetime import timedelta, timezone  # Validate UTC election windows.
from Crypto.Hash import SHA256  # Hash the signed authority timestamp.

def load_json(path, default=None):  # Load earlier records after a restart.
    if not Path(path).exists():  # First run has no database file yet.
        return default  # Return a fresh value.
    return json.loads(Path(path).read_text(encoding="utf-8"))  # Parse saved JSON.


def save_json(path, value):  # Persist keys or records after each change.
    target = Path(path)  # Resolve the destination file.
    temporary = target.with_suffix(target.suffix + ".tmp")  # Write a temporary copy first.
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")  # Serialize the new state.
    temporary.replace(target)  # Replace the old file only after writing completes.


def aes_cbc_pack(text, key):  # Encrypt UTF-8 text using AES-CBC with a fresh IV.
    iv = get_random_bytes(16)  # Generate a 16-byte IV for this record.
    ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(text.encode(), 16))  # Pad and encrypt.
    return {"iv": iv.hex(), "ciphertext": ciphertext.hex()}  # Make bytes JSON-safe.


def aes_cbc_unpack(package, key):  # Decrypt AES-CBC text for an authorized operation.
    raw = AES.new(key, AES.MODE_CBC, bytes.fromhex(package["iv"])).decrypt(bytes.fromhex(package["ciphertext"]))  # Restore bytes.
    return unpad(raw, 16).decode()  # Remove padding and decode text.


def choose_menu(title, choices):  # Run a role menu until the user goes back.
    while True:  # Repeat so all functions can be demonstrated.
        print("\n" + title)  # Show the selected role.
        for number, label in choices.items():  # Display all available actions.
            print(number, label)  # Keep numbered choices explicit.
        answer = input("Choose: ").strip()  # Ask for one action.
        if answer == "0":  # Zero is always Back.
            return  # Leave only this role menu.
        yield answer  # Let the caller handle each action.


# ==================== EXAMPLE A: SECURE GRANT EXPENSE PORTAL ====================

def grant_setup(folder):  # Make and persist keys before creating any grant records.
    path = folder / "grant_keys.json"  # Keep the same keys across program restarts.
    keys = load_json(path)  # Try an existing key file.
    if keys is None:  # Generate keys only once.
        rsa = RSA.generate(2048)  # Generate the researcher's RSA signing key.
        public, private = paillier_keygen(1024)  # Generate Paillier public/private keys.
        keys = {"aes": get_random_bytes(24).hex(), "rsa": rsa.export_key().decode(),
                "paillier_public": public, "paillier_private": private,
                "index": get_random_bytes(32).hex()}  # Save 24-byte AES-192 key and search key.
        save_json(path, keys)  # Preserve keys for earlier records.
    return keys  # Give roles access to the lab demo's key store.


def grant_submit(folder, keys, grant_id, description, amount):  # Researcher builds one complete record.
    grant_id = grant_id.strip()  # Normalize the public identifier.
    if not grant_id or not description.strip() or amount < 0:  # Reject missing data and negative expenses.
        raise ValueError("Grant ID/description required; amount must be nonnegative.")  # Explain failure.
    path = folder / "grants.json"  # Use a persistent record file.
    records = load_json(path, [])  # Load grants entered in earlier runs.
    token = search_token("grant:" + grant_id, bytes.fromhex(keys["index"]))  # Index ID without storing it in clear.
    if any(row["id_token"] == token for row in records):  # Enforce unique Grant IDs.
        raise ValueError("Grant ID already exists.")  # Avoid accidental overwrite.
    body = {"id_token": token, "description": aes_cbc_pack(description, bytes.fromhex(keys["aes"])),
            "amount": str(paillier_encrypt(amount, keys["paillier_public"]))}  # Encrypt each sensitive field.
    digest = hashlib.md5(canonical_bytes(body)).hexdigest()  # Hash ALL stored fields; MD5 is specified by question.
    signature = rsa_sign_md5(canonical_bytes(body), RSA.import_key(keys["rsa"]))  # Sign the same canonical body.
    records.append({**body, "md5": digest, "signature": signature.hex()})  # Save hash and signature.
    save_json(path, records)  # Persist even if program exits now.
    return records[-1]  # Return the submitted record for visible output.


def grant_verify(row, keys):  # Reviewer verifies integrity and researcher authenticity.
    try:  # Malformed or tampered records must not crash the menu.
        body = {key: row[key] for key in ("id_token", "description", "amount")}  # Reconstruct the signed fields.
        raw = canonical_bytes(body)  # Recreate the exact bytes originally signed.
        hash_ok = secrets.compare_digest(hashlib.md5(raw).hexdigest(), row["md5"])  # Detect changed fields.
        sig_ok = rsa_verify_md5(raw, bytes.fromhex(row["signature"]), RSA.import_key(keys["rsa"]).publickey())  # Verify RSA.
        return hash_ok, sig_ok  # Both checks must succeed to trust the record.
    except (KeyError, ValueError, TypeError):  # JSON corruption or invalid hex.
        return False, False  # Treat malformed records as invalid.


def grant_search(folder, keys, grant_id):  # Look up an encrypted record by blind Grant-ID index.
    token = search_token("grant:" + grant_id.strip(), bytes.fromhex(keys["index"]))  # Create the same search token.
    return [row for row in load_json(folder / "grants.json", []) if row.get("id_token") == token]  # No decryption.


def grant_aggregate(folder, keys, grant_ids):  # Finance computes a sum without decrypting each amount.
    selected = []  # Collect only selected and verified grant rows.
    for grant_id in grant_ids:  # Process every requested Grant ID.
        matches = grant_search(folder, keys, grant_id)  # Find encrypted records.
        if len(matches) != 1 or grant_verify(matches[0], keys) != (True, True):  # Reject missing or altered grants.
            raise ValueError("Missing or tampered grant: " + grant_id)  # Abort entire aggregate.
        selected.append(matches[0])  # Add the verified ciphertext.
    if not selected:  # Avoid a meaningless empty total.
        raise ValueError("Select at least one grant.")  # Tell user how to fix input.
    combined = paillier_add([row["amount"] for row in selected], keys["paillier_public"])  # Sum ciphertexts.
    total = paillier_decrypt(combined, keys["paillier_public"], keys["paillier_private"])  # Decrypt final only.
    return combined, total  # Display both encrypted aggregate and final expenditure.


def grant_menu(folder):  # Separate researcher, reviewer, and finance actions.
    folder.mkdir(parents=True, exist_ok=True)  # Ensure demo storage exists.
    keys = grant_setup(folder)  # Reuse persistent keys.
    while True:  # Return to role selection after Back.
        print("\nGRANT PORTAL: 1 Researcher | 2 Reviewer | 3 Finance | 0 Exit")  # Show roles.
        role = input("Role: ").strip()  # Read role selection.
        if role == "0":  # Exit the program.
            return  # Finish main loop.
        actions = {"1": {"1": "Submit grant", "2": "View submitted encrypted records", "0": "Back"},
                   "2": {"1": "Verify all", "2": "Search by Grant ID", "3": "Verified description hex dump", "0": "Back"},
                   "3": {"1": "Verify and aggregate selected grants", "0": "Back"}}  # Apply menu permissions.
        if role not in actions:  # Handle unknown role.
            print("Invalid role.")  # Ask again.
            continue  # Restart role selector.
        for action in choose_menu("Grant role " + role, actions[role]):  # Run the role's permitted operations.
            try:  # Catch bad input without losing menu access.
                if role == "1" and action == "1":  # Researcher enters grant data.
                    grant_id = input("Grant ID: ")  # Read searchable identifier.
                    description = input("Description: ")  # Read private text.
                    amount = int(input("Amount (integer units): "))  # Read Paillier-compatible integer.
                    print("Stored encrypted record:", grant_submit(folder, keys, grant_id, description, amount))  # Show output.
                elif role == "1" and action == "2":  # Researcher views all prior submissions.
                    print("Stored records:", load_json(folder / "grants.json", []))  # Display only encrypted fields.
                elif role == "2" and action == "1":  # Reviewer verifies every stored row.
                    for i, row in enumerate(load_json(folder / "grants.json", [])):  # Number results.
                        print(i, "MD5/RSA valid:", grant_verify(row, keys))  # Show both outcomes.
                elif role == "2" and action in ("2", "3"):  # Reviewer searches without decrypting index.
                    matches = grant_search(folder, keys, input("Grant ID: "))  # Find exact token.
                    print("Matches:", len(matches))  # Show search output.
                    for row in matches:  # Visit matching records.
                        valid = grant_verify(row, keys)  # Check before decrypting.
                        print("MD5/RSA valid:", valid, "Encrypted record:", row)  # Show verification and ciphertext.
                        if action == "3" and valid == (True, True):  # Only trusted record can be decrypted.
                            plain = aes_cbc_unpack(row["description"], bytes.fromhex(keys["aes"]))  # Decrypt description.
                            print("Description UTF-8 hex dump:", plain.encode().hex(" "))  # Show hexadecimal bytes.
                elif role == "3" and action == "1":  # Finance selects grants for secure total.
                    ids = [item.strip() for item in input("Grant IDs, comma-separated: ").split(",") if item.strip()]  # Parse selection.
                    combined, total = grant_aggregate(folder, keys, ids)  # Verify, sum ciphertexts, decrypt final.
                    print("Encrypted aggregate:", combined, "Final total:", total)  # Show both outputs.
                else:  # Reject bad action.
                    print("Invalid option.")  # Continue menu.
            except (ValueError, KeyError, UnicodeError) as exc:  # Handle invalid input or changed data.
                print("Operation failed:", exc)  # Explain without ending program.


# ==================== EXAMPLE B: MENU-DRIVEN E-VOTING ====================

def split_private_for_demo(private, folder):  # Split key material into 2-of-3 Shamir shares for classroom simulation.
    prime = getPrime(1152)  # Choose a field larger than 1024-bit Paillier secret values.
    while prime <= max(private.values()):  # Ensure every secret fits in the field.
        prime = getPrime(1152)  # Retry only if needed.
    slopes = {name: secrets.randbelow(prime) for name in private}  # Fresh linear polynomial per secret.
    for authority in (1, 2, 3):  # Evaluate each polynomial at its authority index.
        share = {"x": authority, "prime": prime,
                 "values": {name: (value + slopes[name] * authority) % prime for name, value in private.items()}}  # Hide secret individually.
        save_json(folder / ("authority_" + str(authority) + ".json"), share)  # Separate lab share file.


def recover_private_for_final(folder, authorities=(1, 2)):  # Reconstruct only immediately before final aggregate decryption.
    shares = [load_json(folder / ("authority_" + str(i) + ".json")) for i in authorities]  # Load two distinct shares.
    if any(s is None for s in shares) or shares[0]["x"] == shares[1]["x"]:  # Require quorum.
        raise ValueError("Two distinct authority shares are required.")  # Fail safely without quorum.
    if shares[0]["prime"] != shares[1]["prime"]:  # Reject inconsistent shares.
        raise ValueError("Authority shares have different moduli.")  # Stop mismatched key recovery.
    prime = shares[0]["prime"]  # Read Shamir field modulus.
    x1, x2 = shares[0]["x"], shares[1]["x"]  # Read interpolation coordinates.
    recovered = {}  # Hold reconstructed lambda and mu in memory.
    for name in ("lambda", "mu"):  # Recover both private Paillier values.
        y1, y2 = shares[0]["values"][name], shares[1]["values"][name]  # Read two polynomial points.
        a = (y2 - y1) * pow(x2 - x1, -1, prime) % prime  # Interpolate linear slope.
        recovered[name] = (y1 - a * x1) % prime  # Evaluate polynomial at zero.
    return recovered  # Caller uses this key on final aggregate only.


def vote_setup(folder, rsa_bits=4096):  # Generate and persist election, timestamp, and tally keys.
    path = folder / "vote_keys.json"  # Store keys once for all later ballots.
    keys = load_json(path)  # Try earlier key file.
    if keys is None:  # Set up first-run demo configuration.
        election = RSA.generate(rsa_bits)  # Election Commission RSA-4096 public key.
        authority = RSA.generate(2048)  # Separate simulated timestamp authority key.
        pub, priv = paillier_keygen(1024)  # One Paillier key pair for all candidates.
        p = getPrime(1024)  # Lab-size prime for textbook ElGamal signatures.
        g = 2  # Choose a demo base; production deployments need reviewed group parameters.
        x = secrets.randbelow(p - 3) + 2  # Keep voter's signing private value secret.
        now = datetime.now(timezone.utc)  # Define a runnable demonstration election window.
        keys = {"rsa": election.export_key().decode(), "authority_rsa": authority.export_key().decode(),
                "paillier_public": pub, "index": get_random_bytes(32).hex(),
                "elgamal": {"p": p, "g": g, "x": x, "y": pow(g, x, p)},
                "start": (now - timedelta(days=1)).isoformat(), "end": (now + timedelta(days=1)).isoformat(),
                "candidates": [1, 2, 3]}  # Make a concrete deadline and candidate list.
        split_private_for_demo(priv, folder)  # Store private Paillier values as 2-of-3 demo shares.
        save_json(path, keys)  # Ensure ballots survive a restart with the same keys.
    return keys  # Return configured election information.


def vote_cast(folder, keys, voter_id, constituency, candidate):  # Client creates an encrypted signed ballot.
    if not voter_id.strip() or not constituency.strip():  # Enforce required fields.
        raise ValueError("Voter ID and constituency required.")  # Reject empty identifiers.
    if candidate not in keys["candidates"]:  # Enforce known candidates.
        raise ValueError("Unknown candidate.")  # Prevent invalid tallies.
    voter_token = search_token("voter:" + voter_id, bytes.fromhex(keys["index"]))  # Pseudonymize voter for one-vote check.
    rows = load_json(folder / "ballots.json", [])  # Load all earlier ballots.
    if any(r.get("voter_token") == voter_token for r in rows):  # Avoid voting twice.
        raise ValueError("Voter already cast a ballot.")  # Reject duplicate submission.
    timestamp = datetime.now(timezone.utc).isoformat()  # Obtain current UTC for the lab authority simulation.
    if not datetime.fromisoformat(keys["start"]) <= datetime.fromisoformat(timestamp) <= datetime.fromisoformat(keys["end"]):  # Check window.
        raise ValueError("Voting period is closed.")  # Do not store a late ballot.
    ballot = {"candidate": candidate, "constituency": constituency}  # Make exact file/ballot data.
    raw = canonical_bytes(ballot)  # Serialize deterministically before hashing.
    digest = hashlib.sha512(raw).digest()  # Compute client-side SHA-512 ballot hash.
    session_key = get_random_bytes(32)  # Make AES-256 session key.
    packed = aes_cbc_pack(raw.decode(), session_key)  # Encrypt ballot with AES-256 CBC.
    rsa = RSA.import_key(keys["rsa"])  # Read the commission's RSA key pair.
    wrapped = PKCS1_OAEP.new(rsa.publickey()).encrypt(session_key)  # Encrypt session key with RSA-4096.
    eg = keys["elgamal"]  # Read simulated voter's ElGamal key.
    sig = elgamal_sign_digest(digest, eg["p"], eg["g"], eg["x"])  # Sign SHA-512 digest.
    authority = RSA.import_key(keys["authority_rsa"])  # Read separate timestamp authority key.
    ts_sig = pkcs1_15.new(authority).sign(SHA256.new(timestamp.encode()))  # Sign time for demo.
    one_hot = {str(c): str(paillier_encrypt(int(candidate == c), keys["paillier_public"]))
               for c in keys["candidates"]}  # Encrypt 1 for selected candidate, 0 for others.
    row = {"voter_token": voter_token,
           "constituency_token": search_token("constituency:" + constituency, bytes.fromhex(keys["index"])),
           "day_token": search_token("day:" + timestamp[:10], bytes.fromhex(keys["index"])),
           "timestamp": timestamp, "timestamp_signature": ts_sig.hex(), "ballot": packed,
           "wrapped_key": wrapped.hex(), "sha512": digest.hex(), "elgamal_signature": list(sig),
           "vote_ciphers": one_hot}  # Save content encrypted plus searchable metadata.
    envelope = {key: row[key] for key in ("voter_token", "constituency_token", "day_token", "timestamp", "ballot", "wrapped_key", "vote_ciphers")}  # Bind all stored fields.
    row["envelope_signature"] = list(elgamal_sign_digest(hashlib.sha512(canonical_bytes(envelope)).digest(), eg["p"], eg["g"], eg["x"]))  # Authenticate ciphertext and index.
    rows.append(row)  # Add new ballot.
    save_json(folder / "ballots.json", rows)  # Persist submission.
    return row  # Return outputs visible in menu.


def vote_verify(row, keys):  # Server validates before any tally or audit.
    try:  # Corrupted hex or malformed JSON must fail gracefully.
        time = datetime.fromisoformat(row["timestamp"])  # Parse authority timestamp.
        authority = RSA.import_key(keys["authority_rsa"]).publickey()  # Use the authority public key.
        pkcs1_15.new(authority).verify(SHA256.new(row["timestamp"].encode()),
                                        bytes.fromhex(row["timestamp_signature"]))  # Authenticate timestamp.
        in_window = datetime.fromisoformat(keys["start"]) <= time <= datetime.fromisoformat(keys["end"])  # Check deadline.
        session_key = PKCS1_OAEP.new(RSA.import_key(keys["rsa"])).decrypt(bytes.fromhex(row["wrapped_key"]))  # Unwrap AES key.
        raw = aes_cbc_unpack(row["ballot"], session_key).encode()  # Restore ballot only for server audit.
        digest = hashlib.sha512(raw).digest()  # Recompute actual ballot file hash.
        hash_ok = secrets.compare_digest(digest.hex(), row["sha512"])  # Detect tampering.
        eg = keys["elgamal"]  # Look up voter's demo public key.
        sig_ok = elgamal_verify_digest(digest, row["elgamal_signature"], eg["p"], eg["g"], eg["y"])  # Verify signer.
        ballot = json.loads(raw)  # Inspect constituency, not individual Paillier vote.
        token_ok = row["constituency_token"] == search_token("constituency:" + ballot["constituency"], bytes.fromhex(keys["index"]))  # Bind index.
        for c in keys["candidates"]:  # Ensure each ciphertext is structurally valid.
            value = int(row["vote_ciphers"][str(c)])  # Read encrypted one-hot component.
            n = keys["paillier_public"]["n"]  # Read Paillier modulus.
            if not 0 < value < n * n or math.gcd(value, n) != 1:  # Check ciphertext group.
                return False, "invalid encrypted vote"  # Reject malformed tally input.
        day_ok = row["day_token"] == search_token("day:" + row["timestamp"][:10], bytes.fromhex(keys["index"]))  # Bind date index.
        envelope = {key: row[key] for key in ("voter_token", "constituency_token", "day_token", "timestamp", "ballot", "wrapped_key", "vote_ciphers")}  # Rebuild signed record.
        envelope_ok = elgamal_verify_digest(hashlib.sha512(canonical_bytes(envelope)).digest(), row["envelope_signature"], eg["p"], eg["g"], eg["y"])  # Detect ciphertext changes.
        valid = in_window and hash_ok and sig_ok and token_ok and day_ok and envelope_ok  # Require every condition.
        return valid, ("valid" if valid else "hash/signature/window/index failed")  # Report status.
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:  # Reject any tampered or incomplete row.
        return False, "verification failed: " + str(exc)  # Never tally this row.


def vote_search(folder, keys, constituency=None, day=None):  # Exact blind-index audit search.
    rows = load_json(folder / "ballots.json", [])  # Read earlier ballots.
    if constituency:  # Optional constituency filter.
        token = search_token("constituency:" + constituency, bytes.fromhex(keys["index"]))  # Create token.
        rows = [r for r in rows if r.get("constituency_token") == token]  # Match encrypted index only.
    if day:  # Optional UTC day bucket filter.
        token = search_token("day:" + day, bytes.fromhex(keys["index"]))  # Create day token.
        rows = [r for r in rows if r.get("day_token") == token]  # Narrow results.
    return rows  # Return encrypted records, not candidate plaintext.


def vote_tally(folder, keys):  # Aggregate one-hot encrypted counts by candidate.
    rows = load_json(folder / "ballots.json", [])  # Read persisted ballots.
    good = []  # Hold only authenticated ballots.
    for i, row in enumerate(rows):  # Check all ballots first.
        valid, reason = vote_verify(row, keys)  # Verify signature, hash, deadline, index.
        if valid:  # Accept ballot after checks.
            good.append(row)  # Include its encrypted vote vector.
        else:  # Exclude altered or late records.
            print("Excluded ballot", i, reason)  # Show audit result.
    results = {}  # Store encrypted aggregate and final count per candidate.
    final_ciphers = {c: paillier_add([row["vote_ciphers"][str(c)] for row in good], keys["paillier_public"]) for c in keys["candidates"]}  # Form all final ciphertexts first.
    private = recover_private_for_final(folder)  # Simulate a 2-of-3 authority quorum for the final result.
    for c in keys["candidates"]:  # Each candidate has its own one-hot column.
        aggregate = final_ciphers[c]  # Read already-computed aggregate ciphertext.
        total = paillier_decrypt(aggregate, keys["paillier_public"], private)  # Decrypt only aggregate after quorum.
        results[c] = {"aggregate_ciphertext": aggregate, "final_count": total}  # Show exact output.
    return len(good), results  # Return verified vote count and per-candidate counts.


def vote_menu(folder):  # Client/server/commission menus for the election scenario.
    folder.mkdir(parents=True, exist_ok=True)  # Create persistence directory.
    keys = vote_setup(folder)  # Load election keys.
    while True:  # Permit multiple actions in one run.
        print("\nE-VOTING: 1 Voter | 2 Server/Auditor | 3 Election Commission | 0 Exit")  # Show roles.
        role = input("Role: ").strip()  # Read selection.
        if role == "0":  # End program.
            return  # Leave the main loop.
        choices = {"1": {"1": "Cast encrypted ballot", "0": "Back"},
                   "2": {"1": "Verify all ballots", "2": "Search encrypted index", "0": "Back"},
                   "3": {"1": "Verify and tally final aggregate", "0": "Back"}}  # Restrict menu actions.
        if role not in choices:  # Handle invalid role.
            print("Invalid role.")  # Ask again.
            continue  # Return to selection.
        for action in choose_menu("Voting role " + role, choices[role]):  # Process selected role.
            try:  # Keep menu alive after user error or tampering.
                if role == "1" and action == "1":  # Voter submits one ballot.
                    voter = input("Voter ID: ")  # Used only for duplicate prevention.
                    constituency = input("Constituency: ")  # Searchable via blind index.
                    candidate = int(input("Candidate ID 1, 2, or 3: "))  # Choose numerical candidate.
                    print("Stored encrypted ballot:", vote_cast(folder, keys, voter, constituency, candidate))  # Show outputs.
                elif role == "2" and action == "1":  # Server checks every ballot.
                    for i, row in enumerate(load_json(folder / "ballots.json", [])):  # Iterate stored rows.
                        print("Ballot", i, vote_verify(row, keys))  # Display validity and reason.
                elif role == "2" and action == "2":  # Auditor searches encrypted metadata.
                    constituency = input("Constituency (blank = any): ").strip()  # Optional exact filter.
                    day = input("UTC day YYYY-MM-DD (blank = any): ").strip()  # Optional date bucket.
                    print("Matching encrypted ballots:", vote_search(folder, keys, constituency, day))  # Display matches.
                elif role == "3" and action == "1":  # Commission computes final count.
                    count, totals = vote_tally(folder, keys)  # Verify, aggregate, decrypt final only.
                    print("Verified ballots:", count, "Final aggregate counts:", totals)  # Show all outputs.
                else:  # Handle unknown action.
                    print("Invalid option.")  # Continue menu.
            except (ValueError, KeyError, UnicodeError) as exc:  # Catch invalid inputs.
                print("Operation failed:", exc)  # Explain and continue.



# ============================================================================
# QUESTION-WORDING WRAPPERS: SEARCH THE PHRASE OR FUNCTION NAME WITH CTRL+F
# ============================================================================

def q_lab7_paillier_add_15_and_25():  # Q says "add encrypted 15 and 25 without decrypting".
    return lab7_paillier_demo()  # Use real Paillier encryption and decrypt only final 40.


def q_lab7_rsa_multiply_7_and_3():  # Q says "multiplicative homomorphic textbook RSA".
    p, q, e = 61, 53, 17  # Small educational RSA primes and exponent.
    n, phi = p * q, (p - 1) * (q - 1)  # Build RSA modulus and Euler value.
    d = pow(e, -1, phi)  # Find the RSA private exponent.
    c7, c3 = pow(7, e, n), pow(3, e, n)  # Encrypt each integer without OAEP padding.
    encrypted_product = rsa_textbook_multiply(c7, c3, n)  # Multiply ciphertexts modulo n.
    return {"E(7)": c7, "E(3)": c3, "E(7*3)": encrypted_product,
            "final_product": pow(encrypted_product, d, n)}  # Decrypt once to check 21.


def q_lab7_elgamal_homomorphic_multiplication():  # Q says "multiply ElGamal encrypted readings".
    public, private = elgamal_generate()  # Create a textbook ElGamal key pair.
    first = elgamal_encrypt_int(7, public)  # Encrypt first factor.
    second = elgamal_encrypt_int(3, public)  # Encrypt second factor.
    combined = elgamal_multiply_ciphertexts(first, second, public[0])  # Multiply paired components.
    return {"E(7)": first, "E(3)": second, "encrypted_product": combined,
            "final_product": elgamal_decrypt_int(combined, public[0], private)}  # Check 21.


def q_lab7_secure_data_sharing_and_sum(values=(15, 25)):  # Q says "separate parties encrypt data then compute total".
    public, private = paillier_keygen(512)  # Make one public key for all contributors.
    encrypted = [paillier_encrypt(int(v), public) for v in values]  # Encrypt at each source.
    aggregate = paillier_add(encrypted, public)  # Add on ciphertexts only.
    return {"encrypted_inputs": encrypted, "encrypted_total": aggregate,
            "final_sum": paillier_decrypt(aggregate, public, private)}  # Open final sum.


def q_lab7_compare_paillier_and_elgamal_performance():  # Q says "benchmark PHE schemes".
    start = time.perf_counter()  # Begin Paillier timing.
    pub, priv = paillier_keygen(512)  # Generate Paillier keys.
    a, b = paillier_encrypt(7, pub), paillier_encrypt(3, pub)  # Encrypt both values.
    total = paillier_decrypt(paillier_add([a, b], pub), pub, priv)  # Sum and decrypt final.
    paillier_seconds = time.perf_counter() - start  # Measure whole Paillier path.
    start = time.perf_counter()  # Begin ElGamal timing.
    pub2, priv2 = elgamal_generate()  # Generate ElGamal keys.
    x, y = elgamal_encrypt_int(7, pub2), elgamal_encrypt_int(3, pub2)  # Encrypt factors.
    product = elgamal_decrypt_int(elgamal_multiply_ciphertexts(x, y, pub2[0]), pub2[0], priv2)  # Multiply/decrypt.
    elgamal_seconds = time.perf_counter() - start  # Measure whole ElGamal path.
    return {"Paillier_sum": total, "Paillier_seconds": paillier_seconds,
            "ElGamal_product": product, "ElGamal_seconds": elgamal_seconds}  # Report unlike operations honestly.


def q_lab8_sse_aes_ten_documents_search():  # Q says "SSE corpus of at least ten AES encrypted documents".
    return lab8_ten_document_demo()  # Build encrypted inverted index and display matching documents.


def q_lab8_paillier_encrypted_document_ids():  # Q says "PKSE/Paillier encrypted index and matching IDs".
    return lab8_paillier_postings_demo()  # Use secret search token; Paillier alone cannot compare query ciphertext.


def q_grant_researcher_submit(folder, keys, grant_id, description, amount):  # Researcher: enter Grant ID/description/amount.
    return grant_submit(Path(folder), keys, grant_id, description, amount)  # Encrypt, hash, sign, persist.


def q_grant_reviewer_verify_search_hex(folder, keys, grant_id):  # Reviewer: search and hex-dump description.
    results = []  # Hold review results.
    for row in grant_search(Path(folder), keys, grant_id):  # Match blind Grant ID without decrypting index.
        hash_ok, signature_ok = grant_verify(row, keys)  # Detect tampering and verify RSA.
        info = {"md5_ok": hash_ok, "rsa_signature_ok": signature_ok, "encrypted_record": row}  # Display result.
        if hash_ok and signature_ok:  # Never decrypt a failed record.
            raw = aes_cbc_unpack(row["description"], bytes.fromhex(keys["aes"])).encode()  # AES-192 decrypt.
            info["description_hex_dump"] = raw.hex(" ")  # Format a real UTF-8 byte hex dump.
        results.append(info)  # Add this search result.
    return results  # Give reviewer all requested outputs.


def q_grant_finance_verify_and_total(folder, keys, grant_ids):  # Finance: select, verify, combine, final decrypt.
    return grant_aggregate(Path(folder), keys, grant_ids)  # Return encrypted aggregate and final total.


def q_vote_client_hash_encrypt_sign_timestamp(folder, keys, voter_id, constituency, candidate_id):  # Voter side.
    return vote_cast(Path(folder), keys, voter_id, constituency, candidate_id)  # Persist complete encrypted ballot.


def q_vote_server_verify_and_search(folder, keys, constituency="", day=""):  # Server side.
    matches = vote_search(Path(folder), keys, constituency or None, day or None)  # Query keyed blind indexes.
    return [(row, vote_verify(row, keys)) for row in matches]  # Check timestamp, SHA-512, signatures, ciphertext.


def q_vote_commission_homomorphic_final_tally(folder, keys):  # Commission side with quorum demo.
    return vote_tally(Path(folder), keys)  # Count encrypted 0/1 columns and decrypt final totals only.


# ============================================================================
# BUILT-IN QUESTION FINDER: "python IS_Exam_Toolkit_Labs_1_to_8.py find"
# ============================================================================

QUESTION_INDEX = [  # Map common question phrases to exact functions to search and copy.
    ("additive caesar shift", "Lab 1", "additive_encrypt / additive_decrypt"),  # Classical shift.
    ("multiplicative affine gcd inverse", "Lab 1", "multiplicative_encrypt / affine_encrypt / affine_decrypt"),  # Invertible key.
    ("vigenere autokey playfair hill", "Lab 1", "vigenere_encrypt / autokey_encrypt / playfair_encrypt / hill_encrypt_2x2"),  # Letter ciphers.
    ("brute-force known plaintext", "Lab 1", "additive_bruteforce / affine_keys_from_known_pair"),  # Attacks.
    ("AES-128 AES-192 AES-256 CBC CTR IV padding", "Lab 2", "aes_cbc_encrypt / aes_cbc_decrypt / aes_ctr_encrypt"),  # Symmetric encryption.
    ("DES 3DES Triple DES modes timing", "Lab 2", "des_encrypt / triple_des_encrypt / time_aes_modes"),  # Other modes.
    ("RSA public key encryption OAEP AES session key", "Lab 3", "rsa_encrypt_bytes / rsa_decrypt_bytes / rsa_hybrid_encrypt"),  # Wrap short key.
    ("ElGamal encryption Diffie-Hellman ECC", "Lab 3", "elgamal_encrypt_int / dh_demo / ecc_hybrid_encrypt"),  # Asymmetric crypto.
    ("Rabin four roots key management RBAC", "Lab 4", "rabin_decrypt_roots / RabinKeyManager / rbac_allowed"),  # Access control.
    ("MD5 SHA-1 SHA-256 SHA-512 hash integrity", "Lab 5", "md5_hex / sha256_hex / hashlib.sha512 / integrity_check"),  # Hashing.
    ("RSA digital signature ElGamal Schnorr non-repudiation", "Lab 6", "rsa_sign_md5 / rsa_verify_md5 / elgamal_sign_digest / schnorr_sign"),  # Signatures.
    ("Paillier homomorphic addition encrypted sum expenditure", "Lab 7", "paillier_keygen / paillier_encrypt / paillier_add / paillier_decrypt"),  # Final-only decrypt.
    ("ElGamal RSA homomorphic multiplication", "Lab 7", "q_lab7_elgamal_homomorphic_multiplication / q_lab7_rsa_multiply_7_and_3"),  # Product.
    ("benchmark homomorphic performance", "Lab 7", "q_lab7_compare_paillier_and_elgamal_performance"),  # Timing.
    ("SSE searchable encryption inverted index AES ten documents", "Lab 8", "q_lab8_sse_aes_ten_documents_search / sse_build_inverted"),  # Search corpus.
    ("PKSE Paillier encrypted index document IDs", "Lab 8", "q_lab8_paillier_encrypted_document_ids"),  # Encrypted IDs.
    ("grant researcher AES-192 MD5 RSA reviewer finance Grant ID", "Scenario", "grant_menu / grant_submit / grant_verify / grant_search / grant_aggregate"),  # Full grant portal.
    ("voting voter SHA-512 AES-256 RSA-4096 ElGamal timestamp threshold constituency", "Scenario", "vote_menu / vote_cast / vote_verify / vote_search / vote_tally"),  # Full election.
    ("persist earlier entries restart role menu invalid input", "Glue", "load_json / save_json / choose_menu / grant_menu / vote_menu"),  # Program structure.
]


def find_exam_functions(question):  # Find exact copyable functions from pasted exam wording.
    words = set(re.findall(r"[a-z0-9]+", question.casefold()))  # Tokenize the question.
    scored = []  # Rank the matched question patterns.
    for cue, lab, functions in QUESTION_INDEX:  # Try every topic.
        if lab == "Scenario" and "grant researcher" in cue and "grant" not in words:  # Require grant context.
            continue  # Avoid suggesting grant scenario for election prompts.
        if lab == "Scenario" and "voting voter" in cue and not ({"vote", "voting", "ballot", "voter", "election"} & words):  # Require election context.
            continue  # Avoid suggesting voting scenario for grant prompts.
        cue_words = set(re.findall(r"[a-z0-9]+", cue.casefold()))  # Tokenize topic.
        overlap = len(words & cue_words)  # Count shared words.
        if overlap:  # Keep relevant patterns.
            scored.append((overlap, lab, cue, functions))  # Add a searchable recommendation.
    for score, lab, cue, functions in sorted(scored, key=lambda item: -item[0])[:12]:  # Display best matches.
        print(f"{lab} | Q says {cue} | SEARCH: {functions}")  # Print exact function names.
    print("CHECK: roles, input(), while menu, saved keys/records, verification, invalid input, every output.")  # Remind of marks.
    print("Read the question again: keyword matches cannot replace its precise conditions.")  # State limitation.


def exam_toolkit_main():  # Run built-in question finder or a complete scenario.
    import sys  # Read optional scenario command argument.
    if len(sys.argv) > 1 and sys.argv[1] in ("grant", "vote"):  # Direct runnable role menus.
        folder = Path("exam_demo_data") / sys.argv[1]  # Store records persistently by scenario.
        (grant_menu if sys.argv[1] == "grant" else vote_menu)(folder)  # Start selected menu.
        return  # Finish after exit.
    if len(sys.argv) > 1 and sys.argv[1] == "find":  # Search function names from question wording.
        print("Paste question; END on its own line:")  # Explain multi-line input.
        lines = []  # Collect question lines.
        while True:  # Keep reading until END or EOF.
            try:  # Accept piped prompts as well.
                line = input()  # Read one line.
            except EOFError:  # End piped input.
                break  # Analyze now.
            if line.strip().upper() == "END":  # User finished pasting.
                break  # Analyze now.
            lines.append(line)  # Keep prompt text.
        find_exam_functions("\n".join(lines))  # Show exact function names.
        return  # Finish finder.
    while True:  # Default interactive launcher.
        print("\nIS LAB TOOLKIT: 1 Find functions | 2 Grant menu | 3 Voting menu | 4 Lab 7/8 demos | 0 Exit")  # Choices.
        choice = input("Choose: ").strip()  # Read numbered menu input.
        if choice == "0":  # Exit.
            return  # Finish program.
        if choice == "1":  # User asks which functions suit a question.
            print("Paste question; END on its own line:")  # Explain input.
            lines = []  # Collect prompt lines.
            while True:  # Read all lines.
                line = input()  # Read next line.
                if line.strip().upper() == "END":  # Stop sentinel.
                    break  # Finish reading.
                lines.append(line)  # Save line.
            find_exam_functions("\n".join(lines))  # Print matches.
        elif choice == "2":  # Grant scenario.
            grant_menu(Path("exam_demo_data/grant"))  # Open grant role menu.
        elif choice == "3":  # E-voting scenario.
            vote_menu(Path("exam_demo_data/vote"))  # Open voting role menu.
        elif choice == "4":  # Small manual lab demonstrations.
            print("Paillier final sum:", q_lab7_paillier_add_15_and_25()["decrypted_final_sum"])  # Show 40.
            print("SSE matches:", q_lab8_sse_aes_ten_documents_search())  # Show encrypted search result.
        else:  # Invalid choice.
            print("Invalid option.")  # Ask again.


if __name__ == "__main__":  # The combined toolkit now runs menus and question finder directly.
    exam_toolkit_main()  # Start top-level menu or requested scenario.
