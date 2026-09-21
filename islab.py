"""
IS LAB EXAM HELPER v3 - UNIVERSAL SCENARIO DECOMPOSER
------------------------------------------------------
Paste a long Information Security lab/midsem question, then type END.

The goal is NOT to magically solve every possible question.
The goal is to turn an overwhelming question into:
    1) algorithms involved
    2) validations/conditions
    3) exact implementation order
    4) toolkit functions to copy
    5) glue code patterns (dictionary/list/menu/files)

Covers the common patterns from Labs 1-6:
- Classical ciphers: Caesar/Additive, Multiplicative, Affine, Vigenere,
  Autokey, Playfair, Hill
- AES / DES / 3DES
- RSA / ElGamal / ECC / Rabin
- Diffie-Hellman
- SHA-256 / SHA-1 / MD5
- RSA / ElGamal / Schnorr signatures
- File handling and hybrid encryption
- Hash/integrity and tampering tests
- Role-based/menu-driven systems
- Multiple records using dictionaries + lists
- Client/server/socket questions
- Performance/timing/collision experiments

IMPORTANT:
This helper assumes you already have your master crypto toolkit functions.
It tells you WHAT to copy and HOW to join the pieces.
"""

import re


# ============================================================
# BASIC HELPERS
# ============================================================

def normalize(text):
    return re.sub(r"\s+", " ", text.lower()).strip()


def contains_any(text, phrases):
    t = normalize(text)
    return any(p.lower() in t for p in phrases)


def title(text):
    print("\n" + "=" * 78)
    print(text)
    print("=" * 78)


def yesno(value):
    return "YES" if value else "NO"


# ============================================================
# ALGORITHM DETECTION
# ============================================================

def detect_algorithms(question):
    q = normalize(question)

    patterns = {
        "AES": [r"\baes\b", r"advanced encryption standard"],
        "DES": [r"(?<!3)\bdes\b", r"data encryption standard"],
        "3DES": [r"\b3des\b", r"triple des", r"des3"],
        "RSA": [r"\brsa\b"],
        "ElGamal": [r"el\s*gamal", r"elgamal"],
        "ECC": [r"\becc\b", r"elliptic curve"],
        "Rabin": [r"\brabin\b"],
        "Diffie-Hellman": [r"diffie\s*[-–]?\s*hellman", r"\bdh\b"],
        "Affine": [r"\baffine\b"],
        "Additive/Caesar": [r"\badditive\b", r"\bcaesar\b", r"shift cipher"],
        "Multiplicative": [r"\bmultiplicative\s+(?:cipher|encryption|decryption)\b"],
        "Vigenere": [r"vigen[eè]re", r"vigenere"],
        "Autokey": [r"auto\s*key", r"autokey"],
        "Playfair": [r"playfair"],
        "Hill": [r"\bhill cipher\b", r"\bhill\b"],
        "Schnorr": [r"schnorr"],
        "SHA-256": [r"sha\s*[-]?\s*256", r"sha256"],
        "SHA-1": [r"sha\s*[-]?\s*1\b", r"sha1\b"],
        "MD5": [r"\bmd5\b"],
    }

    found = []
    for name, pats in patterns.items():
        if any(re.search(p, q, re.I) for p in pats):
            found.append(name)

    return found


# ============================================================
# ROLE / ACTOR DETECTION
# ============================================================

def detect_roles(question):
    """Find actual actors/roles without treating words like 'patient data' as a role."""

    known = [
        "Compliance Officer", "Hospital Server", "Administrator", "Doctor",
        "Nurse", "Admin", "Patient", "Auditor", "Sender", "Receiver",
        "Faculty", "Student", "Manager", "Finance", "Employee", "Client",
        "Lawyer", "Server", "HR", "Customer", "Alice", "Bob"
    ]

    found = []

    def add_role(role):
        for known_role in known:
            if role.lower().strip() == known_role.lower():
                if known_role not in found:
                    found.append(known_role)
                return

    # 1) Explicit headings: Doctor:, NURSE, Sender Side, etc.
    for raw in question.splitlines():
        line = raw.strip().strip("*-# ")
        for role in known:
            if re.fullmatch(re.escape(role) + r"(?:\s+side)?\s*: ?", line, re.I) or \
               re.fullmatch(re.escape(role) + r"(?:\s+side)?", line, re.I):
                add_role(role)

    # 2) Natural phrases: "The Doctor should...", "Receiver must..."
    for role in known:
        if re.search(r"\b(?:the\s+)?" + re.escape(role) + r"\s+(?:should|must|can|is allowed|will|computes|enters|receives|sends)\b", question, re.I):
            add_role(role)

    # 3) "consists of a Sender and a Receiver"
    for role in known:
        if re.search(r"\bconsists?\s+of[^.\n]{0,100}\b" + re.escape(role) + r"\b", question, re.I):
            add_role(role)

    # 4) Explicit role list such as "roles: Doctor, Nurse, Admin".
    for m in re.finditer(r"\broles?\b\s*(?:are|:|=)?\s*([^\n.]{1,120})", question, re.I):
        chunk = m.group(1)
        for role in known:
            if re.search(r"\b" + re.escape(role) + r"\b", chunk, re.I):
                add_role(role)

    return found


# ============================================================
# CONSTANT / VALUE EXTRACTION
# ============================================================

def extract_values(question):
    q = question
    values = {}

    def first_int(pattern):
        m = re.search(pattern, q, re.I)
        return int(m.group(1)) if m else None

    values["k2"] = first_int(r"\bk2\s*=\s*(-?\d+)")
    values["k1"] = first_int(r"\bk1\s*=\s*(-?\d+)")
    values["p"] = first_int(r"(?:^|[^A-Za-z])p\s*=\s*(\d+)")
    values["g"] = first_int(r"(?:^|[^A-Za-z])g\s*=\s*(\d+)")

    aes_bits = first_int(r"aes\s*[- ]?\s*(128|192|256)")
    if aes_bits:
        values["aes_bits"] = aes_bits

    rsa_bits = first_int(r"rsa\s*[- ]?\s*(1024|2048|3072|4096)")
    if rsa_bits:
        values["rsa_bits"] = rsa_bits

    files = re.findall(r"[A-Za-z0-9_\- ]+\.(?:txt|bin|dat|enc|csv|json)", q, re.I)
    cleaned_files = []
    for f in files:
        f = f.strip(" `\"'.,:;()[]")
        if f and f not in cleaned_files:
            cleaned_files.append(f)
    values["files"] = cleaned_files

    return values


# ============================================================
# REQUIREMENT / FEATURE DETECTION
# ============================================================

def detect_features(question, algorithms):
    q = normalize(question)

    f = {}

    f["encrypt"] = contains_any(q, ["encrypt", "encryption", "confidentiality"])
    f["decrypt"] = contains_any(q, ["decrypt", "decryption", "recover plaintext", "original plaintext"])

    f["hash"] = contains_any(q, ["hash", "sha-256", "sha256", "sha-1", "md5", "integrity"])
    f["verify_hash"] = contains_any(q, [
        "recompute", "recalculate", "compare it with", "compare with the stored hash",
        "verify integrity", "integrity verification", "check integrity"
    ])

    f["sign"] = contains_any(q, ["digitally sign", "digital signature", "sign the hash", "sign the encrypted", "signature"])
    f["verify_signature"] = (
        contains_any(q, ["verify signature", "verify the signature", "signature verification", "verify authenticity", "valid or invalid"])
        or bool(re.search(r"verify\w*[^.\n]{0,40}signature", q, re.I))
    )

    f["file_input"] = contains_any(q, [
        "read a file", "read from a", "create a file", ".txt file", "file content", "file contents"
    ])
    f["file_output"] = contains_any(q, [
        "store in another file", "write", "save", "another file", "recovered file", "decrypted file"
    ])
    f["binary_file"] = contains_any(q, [".bin", "binary file", "encrypted file"])

    f["timestamp"] = contains_any(q, ["timestamp", "date and time", "current time"])
    f["store"] = contains_any(q, ["store", "save", "record", "records", "secure storage"])
    f["multiple_records"] = contains_any(q, ["records", "previously stored", "available records", "record id", "multiple records"])

    f["rbac"] = contains_any(q, ["role-based", "role based", "rbac", "roles", "authorized operations", "access restrictions"])
    f["menu"] = contains_any(q, ["menu-driven", "menu driven", "menu based"])

    f["encrypt_key"] = contains_any(q, [
        "encrypt the aes key", "encrypt aes key", "encrypted aes key",
        "protect the aes key", "encrypt the des key", "encrypted key"
    ])

    f["tamper"] = contains_any(q, [
        "tamper", "tampering", "modify one byte", "modify one character",
        "alter ciphertext", "change one byte", "integrity failed"
    ])

    f["performance"] = contains_any(q, [
        "performance", "computation time", "execution time", "encryption time",
        "decryption time", "key generation time", "measure time", "benchmark",
        "1 mb", "10 mb", "1mb", "10mb"
    ])

    f["collision"] = contains_any(q, ["collision", "collision resistance", "collision detection"])
    f["client_server"] = contains_any(q, ["client-server", "client server", "socket", "server side", "client side"])

    # FieldTrack / validation style
    f["preprocess_upper_alpha"] = contains_any(q, [
        "convert the plaintext to uppercase", "convert plaintext to uppercase",
        "retain only alphabetic", "only alphabetic characters", "discarded"
    ])

    f["dh_shared"] = "Diffie-Hellman" in algorithms or contains_any(q, ["shared secret", "shared key using diffie"])
    f["compare_shared"] = contains_any(q, [
        "shared secrets are equal", "shared secret is equal", "shared secrets do not match",
        "verify that both shared", "computed shared secret is equal"
    ])

    f["k_mod_validation"] = bool(re.search(r"\bk\s*(?:mod|%)\s*26\s*==\s*k2", q, re.I)) or contains_any(q, ["k mod 26 == k2"])
    f["gcd_validation"] = bool(re.search(r"gcd\s*\(\s*k1\s*,\s*26\s*\)\s*==?\s*1", q, re.I)) or contains_any(q, ["gcd(k1, 26)", "gcd(k1,26)"])
    f["mod_inverse"] = contains_any(q, ["multiplicative inverse", "modular inverse", "inverse of k1"])

    f["uppercase_output"] = f["preprocess_upper_alpha"]

    return f


# ============================================================
# TOOLKIT FUNCTION MAPPING
# ============================================================

def toolkit_functions(algorithms, f):
    funcs = []

    def add(*items):
        for item in items:
            if item not in funcs:
                funcs.append(item)

    if "AES" in algorithms:
        add("aes_cbc_encrypt(plaintext, key, iv=None)",
            "aes_cbc_decrypt(ciphertext, key, iv)",
            "get_random_bytes(16)   # AES-128")

    if "DES" in algorithms:
        add("des_cbc_encrypt(...) / des_cbc_decrypt(...) from toolkit")

    if "3DES" in algorithms:
        add("des3_encrypt(...) / des3_decrypt(...) from toolkit")

    if "RSA" in algorithms:
        add("rsa_generate(2048)")
        if f["encrypt_key"] or f["encrypt"]:
            add("rsa_encrypt_bytes(data, public_key)",
                "rsa_decrypt_bytes(ciphertext, private_key)")
        if f["sign"] or f["verify_signature"]:
            add("rsa_sign_sha256(data, private_key)",
                "rsa_verify_sha256(data, signature, public_key)")

    if "ElGamal" in algorithms:
        add("elgamal_generate(...) / elgamal_encrypt_text(...) / elgamal_decrypt_text(...)")
        if f["sign"] or f["verify_signature"]:
            add("ElGamal sign/verify functions from toolkit")

    if "ECC" in algorithms:
        add("ECC / hybrid helper functions from toolkit")

    if "Diffie-Hellman" in algorithms or f["dh_shared"]:
        add("dh_generate_public(p, g, private=None)",
            "dh_shared_secret(other_public, private, p)")

    if "Affine" in algorithms:
        add("clean_letters(text)",
            "affine_encrypt(text, k1, k2)",
            "affine_decrypt(ciphertext, k1, k2)",
            "math.gcd(k1, 26)",
            "pow(k1, -1, 26)")

    if "Additive/Caesar" in algorithms:
        add("additive_encrypt(...) / additive_decrypt(...)")

    if "Multiplicative" in algorithms:
        add("multiplicative_encrypt(...) / multiplicative_decrypt(...)")

    if "Vigenere" in algorithms:
        add("vigenere_encrypt(...) / vigenere_decrypt(...)")

    if "Autokey" in algorithms:
        add("autokey_encrypt(...) / autokey_decrypt(...)")

    if "Playfair" in algorithms:
        add("playfair helpers from toolkit")

    if "Hill" in algorithms:
        add("hill cipher helpers from toolkit")

    if "Schnorr" in algorithms:
        add("Schnorr sign/verify helpers from toolkit")

    if "Rabin" in algorithms:
        add("rabin_generate_small(...) / rabin_encrypt(...) / rabin_decrypt_roots(...)")

    if f["hash"]:
        add("sha256_hex(data)   # if SHA-256 is required")

    if f["timestamp"]:
        add("timestamp_now()")

    return funcs


# ============================================================
# SPECIALIZED IMPLEMENTATION PLANS
# ============================================================

def print_fieldtrack_plan(values):
    k2 = values.get("k2")
    if k2 is None:
        k2 = 2

    title("SPECIAL PLAN: DIFFIE-HELLMAN + AFFINE")

    print("This is NOT an AES/RSA-style question. Treat it as 2 joined blocks:\n")
    print("BLOCK A: Diffie-Hellman produces the shared secret K")
    print("BLOCK B: K is validated, then Affine does message encryption/decryption\n")

    steps = [
        "Read the given DH parameters p and g (and private values if the question provides them).",
        "Generate Sender public value and Receiver public value.",
        "Sender computes its shared secret using Receiver public + Sender private.",
        "Receiver computes its shared secret using Sender public + Receiver private.",
        "Compare the two shared secrets BEFORE any encryption.",
        "Process plaintext: uppercase + keep A-Z only.",
        f"Set k2 = {k2}.",
        f"Set K = Sender shared secret and check K % 26 == {k2}.",
        "Only after that, ask for k1.",
        "Check math.gcd(k1, 26) == 1.",
        "Only if k1 is valid, compute pow(k1, -1, 26).",
        "Encrypt processed plaintext with affine_encrypt(plaintext, k1, k2).",
        "Receiver sets K = Receiver shared secret and repeats the required validations.",
        "Decrypt the CIPHERTEXT with affine_decrypt(ciphertext, k1, k2).",
        "Display the recovered processed plaintext."
    ]

    for i, step in enumerate(steps, 1):
        print(f"{i}. {step}")

    print("\nMOST COMMON MISTAKES:")
    print("- Using different p values during DH public-value generation and shared-secret calculation.")
    print("- Asking for k1 before K % 26 == k2 passes.")
    print("- Using an invalid k1 after gcd(k1,26) != 1.")
    print("- Decrypting plaintext instead of decrypting the ciphertext.")
    print("- Generating/asking for a different k1 on Receiver side.")



def print_hybrid_plan(algorithms, f):
    if not ("AES" in algorithms and "RSA" in algorithms and f["encrypt_key"]):
        return

    title("SPECIAL PLAN: HYBRID AES + RSA")
    print("Think of it as:\n")
    print("actual data/file --AES--> ciphertext")
    print("AES key          --RSA public of receiver--> encrypted AES key")
    print("\nReceiver does the reverse:")
    print("encrypted AES key --RSA private of receiver--> recovered AES key")
    print("ciphertext + recovered AES key + IV --AES--> plaintext")

    if f["hash"]:
        print("\nIntegrity: hash the CIPHERTEXT, store hash, recompute later.")
    if f["sign"]:
        print("Authenticity: sender/creator PRIVATE key signs; sender/creator PUBLIC key verifies.")


# ============================================================
# GENERAL IMPLEMENTATION ORDER
# ============================================================

def build_general_flow(algorithms, f):
    steps = []

    if f["file_input"]:
        steps.append("Create/read the required input file and load its contents into a variable.")

    if f["preprocess_upper_alpha"]:
        steps.append("Preprocess plaintext exactly as asked (uppercase + alphabetic characters only).")

    if f["dh_shared"]:
        steps.append("Perform Diffie-Hellman: generate public values and independently compute both shared secrets.")

    if f["compare_shared"]:
        steps.append("Compare Sender and Receiver shared secrets; stop if they differ.")

    if f["k_mod_validation"]:
        steps.append("Validate K mod 26 == k2 before requesting/using k1.")

    if f["gcd_validation"]:
        steps.append("Validate gcd(k1, 26) == 1; invalid k1 must not be used.")

    if f["mod_inverse"]:
        steps.append("Compute modular inverse only after k1 validation succeeds.")

    if "AES" in algorithms:
        steps.append("Generate/obtain AES key (+ IV for CBC) and AES-encrypt the actual data/file.")

    if "DES" in algorithms and "AES" not in algorithms:
        steps.append("Generate/obtain DES key (+ IV for CBC) and DES-encrypt the data.")

    if "RSA" in algorithms and f["encrypt"] and not f["encrypt_key"] and "AES" not in algorithms:
        steps.append("Generate RSA key pair and encrypt plaintext with the required RSA public key.")

    if f["encrypt_key"] and "RSA" in algorithms:
        steps.append("RSA-encrypt the AES/DES key using the RECEIVER's public key.")

    if "Affine" in algorithms and f["encrypt"]:
        steps.append("Affine-encrypt processed plaintext using validated k1 and k2.")

    if f["hash"]:
        steps.append("Compute the required hash (usually of ciphertext when the question says integrity of encrypted data).")

    if f["sign"]:
        steps.append("Digitally sign the required data/hash using the SIGNER's private key.")

    if f["timestamp"]:
        steps.append("Generate timestamp_now().")

    if f["store"]:
        steps.append("Store all required values in one record dictionary; append to records[] if multiple records are needed.")

    if f["file_output"]:
        steps.append("Write encrypted/recovered values to the requested output files using the correct file mode.")

    if f["verify_hash"]:
        steps.append("Recompute hash from the received/stored data and compare with the stored hash.")

    if f["verify_signature"]:
        steps.append("Verify signature using the SIGNER's public key.")

    if f["tamper"]:
        steps.append("Modify one ciphertext byte/bit, recompute checks, and show verification failure.")

    if f["decrypt"]:
        if "Affine" in algorithms:
            steps.append("Receiver decrypts the CIPHERTEXT with affine_decrypt(ciphertext, k1, k2) after validations pass.")
        elif f["verify_hash"] or f["verify_signature"]:
            steps.append("Decrypt/display plaintext ONLY after all required verification checks pass.")
        else:
            steps.append("Decrypt using the matching key/IV or private key as required.")

    if f["performance"]:
        steps.append("Measure required operations with time.perf_counter() and print/compare timings.")

    if f["collision"]:
        steps.append("Store seen hash values and report whether any two different inputs produced the same hash.")

    if f["client_server"]:
        steps.append("Split logic into sender/client and receiver/server: send required bytes and verify/decrypt on the other side.")

    return steps


# ============================================================
# GLUE CODE - THE PART THAT USUALLY FEELS OVERWHELMING
# ============================================================

def print_glue_help(roles, algorithms, f, values):
    title("GLUE CODE CHEAT SHEET")

    printed = False

    # Dictionaries and records
    if f["store"] or f["multiple_records"] or f["rbac"]:
        printed = True
        print("\n[A] ONE RECORD = ONE DICTIONARY")
        print('record = {')
        print('    "id": len(records) + 1,')
        if f["encrypt"]:
            print('    "encrypted": encrypted,')
        if "AES" in algorithms:
            print('    "iv": iv,')
        if f["encrypt_key"]:
            print('    "encrypted_key": encrypted_key,')
        if f["hash"]:
            print('    "hash": stored_hash,')
        if f["sign"]:
            print('    "signature": signature,')
        if f["timestamp"]:
            print('    "timestamp": timestamp_now(),')
        print('}')

        print("\n[B] MANY RECORDS = LIST")
        print("records = []")
        print("records.append(record)")
        print("for record in records:")
        print('    print(record["id"])')

    # Menu / RBAC
    if f["rbac"] or f["menu"] or len(roles) >= 3:
        printed = True
        menu_roles = roles[:6] if roles else ["Role1", "Role2", "Role3"]
        print("\n[C] EASY RBAC / MENU")
        print("while True:")
        for i, role in enumerate(menu_roles, 1):
            print(f'    print("{i}. {role}")')
        print('    print("0. Exit")')
        print('    role = input("Choose role: ")')
        for i, role in enumerate(menu_roles, 1):
            word = "if" if i == 1 else "elif"
            print(f'    {word} role == "{i}":')
            print(f'        # {role} operations only')
            print('        pass')
        print('    elif role == "0":')
        print('        break')

    # File modes
    if f["file_input"] or f["file_output"]:
        printed = True
        print("\n[D] FILE HANDLING")
        print('# Create normal text file')
        print('with open("input.txt", "w") as file:')
        print('    file.write("sample data")')
        print()
        print('# Read file as bytes for crypto')
        print('with open("input.txt", "rb") as file:')
        print('    data = file.read()')
        print()
        print('# Store encrypted bytes')
        print('with open("encrypted.bin", "wb") as file:')
        print('    file.write(encrypted)')
        print()
        print('# Read encrypted bytes back')
        print('with open("encrypted.bin", "rb") as file:')
        print('    encrypted = file.read()')
        print()
        print('# Write recovered plaintext bytes')
        print('with open("recovered.txt", "wb") as file:')
        print('    file.write(decrypted)')
        print()
        print('REMEMBER: w=text write, rb=read bytes, wb=write bytes')

    # Patient/student/etc. multiple fields
    if f["rbac"] or f["multiple_records"]:
        printed = True
        print("\n[E] MULTIPLE INPUT FIELDS")
        print('data_obj = {')
        print('    "name": input("Enter name: "),')
        print('    "details": input("Enter details: ")')
        print('}')
        print('data_text = str(data_obj)  # encrypt this string')

    # Tampering
    if f["tamper"]:
        printed = True
        print("\n[F] TAMPERING")
        print("tampered = bytearray(encrypted)")
        print("tampered[0] ^= 1")
        print("tampered = bytes(tampered)")

    # Performance
    if f["performance"]:
        printed = True
        print("\n[G] TIMING")
        print("start = time.perf_counter()")
        print("# operation here")
        print("elapsed = time.perf_counter() - start")
        print('print("Time:", elapsed)')

    # FieldTrack/DH-Affine validation snippet
    if "Diffie-Hellman" in algorithms and "Affine" in algorithms:
        printed = True
        k2 = values.get("k2") if values.get("k2") is not None else 2
        print("\n[H] DH + AFFINE VALIDATION SKELETON")
        print("sender_public, sender_private = dh_generate_public(p, g, sender_private)")
        print("receiver_public, receiver_private = dh_generate_public(p, g, receiver_private)")
        print("sender_secret = dh_shared_secret(receiver_public, sender_private, p)")
        print("receiver_secret = dh_shared_secret(sender_public, receiver_private, p)")
        print()
        print("if sender_secret != receiver_secret:")
        print('    print("Shared secrets do not match")')
        print("else:")
        print(f"    k2 = {k2}")
        print("    if sender_secret % 26 != k2:")
        print('        print("K mod 26 validation failed")')
        print("    else:")
        print('        k1 = int(input("Enter k1: "))')
        print("        if math.gcd(k1, 26) != 1:")
        print('            print("Invalid k1")')
        print("        else:")
        print("            k1_inv = pow(k1, -1, 26)")
        print("            encrypted = affine_encrypt(plaintext, k1, k2)")
        print("            # Receiver uses SAME k1 and decrypts encrypted, not plaintext")
        print("            if receiver_secret % 26 == k2:")
        print("                decrypted = affine_decrypt(encrypted, k1, k2)")

    if not printed:
        print("No special glue structure detected. Focus on the algorithm-specific functions above.")


# ============================================================
# EXAM MEMORY RULES
# ============================================================

def print_rules(algorithms, f):
    title("5-SECOND EXAM RULES")

    print("PUBLIC key  -> encrypt")
    print("PRIVATE key -> decrypt")
    print("PRIVATE key -> sign")
    print("PUBLIC key  -> verify signature")

    if f["hash"]:
        print("Hash = integrity: store old hash, recompute later, compare.")

    if "AES" in algorithms:
        print("AES-128 = 16-byte key. CBC also needs a 16-byte IV.")

    if f["encrypt_key"]:
        print("Large file/data -> AES. RSA protects the small AES key.")

    if f["verify_hash"] or f["verify_signature"]:
        print("If question says verify before access: DO NOT decrypt until checks pass.")

    if "Diffie-Hellman" in algorithms:
        print("Diffie-Hellman establishes a shared secret; it does not itself encrypt the message.")

    if "Affine" in algorithms:
        print("Affine: k1 must be coprime with 26; k2 is the additive part.")

    if f["file_input"] or f["file_output"]:
        print("Crypto works on DATA read from a file, not on the filename itself.")

    if f["rbac"]:
        print("Easy RBAC for lab: separate role blocks; do not put forbidden operations in that role's block.")


# ============================================================
# MAIN ANALYZER
# ============================================================

def analyze_question(question):
    algorithms = detect_algorithms(question)
    roles = detect_roles(question)
    values = extract_values(question)
    f = detect_features(question, algorithms)

    title("1. QUESTION DECOMPOSITION")

    print("Algorithms detected:")
    if algorithms:
        for a in algorithms:
            print("  -", a)
    else:
        print("  - No named algorithm detected. Read algorithm names manually.")

    print("\nActors / roles detected:")
    if roles:
        for r in roles:
            print("  -", r)
    else:
        print("  - No clear role names detected")

    print("\nImportant requirements detected:")
    labels = [
        ("encrypt", "Encryption"),
        ("decrypt", "Decryption"),
        ("hash", "Hash / integrity"),
        ("verify_hash", "Recompute / compare hash"),
        ("sign", "Digital signature"),
        ("verify_signature", "Signature verification"),
        ("file_input", "Read/create file"),
        ("file_output", "Write/store file"),
        ("encrypt_key", "Encrypt/wrap AES/DES key"),
        ("timestamp", "Timestamp"),
        ("store", "Store record/data"),
        ("multiple_records", "Multiple records / record IDs"),
        ("rbac", "RBAC / role restrictions"),
        ("menu", "Menu-driven system"),
        ("tamper", "Tampering test"),
        ("performance", "Timing / performance"),
        ("collision", "Collision detection"),
        ("client_server", "Client-server / socket"),
        ("preprocess_upper_alpha", "Uppercase + A-Z-only preprocessing"),
        ("dh_shared", "Diffie-Hellman shared secret"),
        ("compare_shared", "Compare both DH shared secrets"),
        ("k_mod_validation", "K mod 26 == k2 validation"),
        ("gcd_validation", "gcd(k1,26) == 1 validation"),
        ("mod_inverse", "Modular inverse of k1"),
    ]

    any_feature = False
    for key, label in labels:
        if f.get(key):
            any_feature = True
            print("  [YES]", label)
    if not any_feature:
        print("  - No common pattern confidently detected")

    detected_values = {k: v for k, v in values.items() if v not in (None, [], "")}
    if detected_values:
        print("\nValues/files detected:")
        for k, v in detected_values.items():
            print(f"  - {k}: {v}")

    # Specialized plan for FieldTrack-like questions
    if "Diffie-Hellman" in algorithms and "Affine" in algorithms:
        print_fieldtrack_plan(values)

    print_hybrid_plan(algorithms, f)

    title("2. IMPLEMENTATION ORDER")
    flow = build_general_flow(algorithms, f)
    if flow:
        for i, step in enumerate(flow, 1):
            print(f"{i}. {step}")
    else:
        print("Could not confidently build a flow. Use algorithm names + question order manually.")

    title("3. FUNCTIONS TO COPY FROM YOUR MASTER TOOLKIT")
    funcs = toolkit_functions(algorithms, f)
    if funcs:
        for fn in funcs:
            print("  -", fn)
    else:
        print("  - No matching toolkit function detected")

    print_glue_help(roles, algorithms, f, values)
    print_rules(algorithms, f)

    title("FINAL EXAM CHECK")
    print("Before coding, answer these 7 questions:")
    print("1. Who are the actors/roles?")
    print("2. What is the plaintext/data/file?")
    print("3. Which algorithm does what?")
    print("4. Which conditions must pass BEFORE continuing?")
    print("5. What must be stored?")
    print("6. Who is allowed to decrypt / verify / only view?")
    print("7. What exact variable is passed to the next function?")


# ============================================================
# INPUT LOOP
# ============================================================

def main():
    print("=" * 78)
    print("IS LAB EXAM HELPER v3 - UNIVERSAL SCENARIO DECOMPOSER")
    print("=" * 78)
    print("Paste the complete question.")
    print("Type END on a new line when finished.\n")

    lines = []

    while True:
        try:
            line = input()
        except EOFError:
            break

        if line.strip().upper() == "END":
            break

        lines.append(line)

    question = "\n".join(lines)

    if not question.strip():
        print("No question entered.")
        return

    analyze_question(question)


if __name__ == "__main__":
    main()
