
"""
IS LAB EXAM HELPER v2
---------------------
Generic question analyzer for Information Security lab exams.

This version DOES NOT depend on exact scenario names such as:
SecureVault, HealthSecure, MediSecure, etc.

It detects requirements from meaning-like keyword groups:
- AES / DES / RSA / ElGamal / SHA
- encryption / decryption
- hashing / integrity
- signatures / authenticity
- public/private key usage
- file handling
- role restrictions
- tampering tests
- timestamps
- menu-driven / RBAC

Paste any similar exam question and type END on a new line.
"""

import re


# ============================================================
# TEXT HELPERS
# ============================================================

def normalize(text):
    return re.sub(r"\s+", " ", text.lower()).strip()


def contains_any(text, phrases):
    t = normalize(text)
    return any(p.lower() in t for p in phrases)


def contains_all(text, phrases):
    t = normalize(text)
    return all(p.lower() in t for p in phrases)


def title(s):
    print("\n" + "=" * 72)
    print(s)
    print("=" * 72)


# ============================================================
# DETECT ALGORITHMS
# ============================================================

def detect_algorithms(q):
    ql = normalize(q)
    found = []

    patterns = {
        "AES": [
            r"\baes\b", r"advanced encryption standard"
        ],
        "DES": [
            r"\bdes\b", r"data encryption standard"
        ],
        "RSA": [
            r"\brsa\b"
        ],
        "ElGamal": [
            r"elgamal", r"el gamal"
        ],
        "Schnorr": [
            r"schnorr"
        ],
        "Diffie-Hellman": [
            r"diffie[- ]hellman", r"\bdh\b"
        ],
        "SHA-256": [
            r"sha[- ]?256", r"secure hash algorithm.*256"
        ],
        "SHA-1": [
            r"sha[- ]?1\b"
        ],
        "MD5": [
            r"\bmd5\b"
        ],
    }

    for algo, pats in patterns.items():
        if any(re.search(p, ql, re.I) for p in pats):
            found.append(algo)

    return found


# ============================================================
# DETECT MODES / CRYPTO DETAILS
# ============================================================

def detect_modes(q):
    ql = normalize(q)
    details = []

    if re.search(r"\bcbc\b", ql):
        details.append("CBC mode")

    if re.search(r"\becb\b", ql):
        details.append("ECB mode")

    if re.search(r"\bgcm\b", ql):
        details.append("GCM mode")

    if re.search(r"\bctr\b", ql):
        details.append("CTR mode")

    if contains_any(ql, ["initialization vector", " iv ", "generate iv", "use iv"]):
        details.append("IV required")

    if contains_any(ql, ["aes-128", "128-bit aes", "128 bit aes"]):
        details.append("AES-128")

    if contains_any(ql, ["2048-bit rsa", "rsa-2048", "2048 bit rsa"]):
        details.append("RSA-2048")

    return details


# ============================================================
# DETECT TASK INTENTS
# ============================================================

def detect_intents(q):
    ql = normalize(q)

    intents = {
        "encrypt_plaintext": contains_any(ql, [
            "encrypt the record", "encrypt patient", "encrypt data",
            "encrypt the file", "encrypt file content",
            "encrypt the message", "confidentiality"
        ]),

        "decrypt_plaintext": contains_any(ql, [
            "decrypt the record", "decrypt patient", "decrypt data",
            "decrypt the file", "decrypt file content",
            "recover plaintext", "recovered plaintext",
            "original file content", "show decrypted"
        ]),

        "hash_data": contains_any(ql, [
            "hash", "sha-256", "sha256",
            "integrity", "digest"
        ]),

        "sign": contains_any(ql, [
            "digitally sign", "digital signature",
            "generate signature", "sign the hash",
            "sign hash", "authentication"
        ]),

        "verify_signature": contains_any(ql, [
            "verify signature", "signature verification",
            "verify the digital signature",
            "verify authenticity", "authenticity verification"
        ]),

        "verify_hash": contains_any(ql, [
            "recompute", "recalculate", "compare hash",
            "verify integrity", "integrity verification",
            "check integrity", "hash verification"
        ]),

        "file_input": contains_any(ql, [
            "read from a file", "read a file", ".txt file",
            "create a file", "file content"
        ]),

        "file_storage": contains_any(ql, [
            "store", "save", "write to file",
            "another file", "stored record", "secure storage"
        ]),

        "timestamp": contains_any(ql, [
            "timestamp", "date and time", "current time"
        ]),

        "rbac": contains_any(ql, [
            "role-based", "role based", "rbac",
            "three roles", "role", "authorized operations"
        ]),

        "menu": contains_any(ql, [
            "menu-driven", "menu driven", "menu based"
        ]),

        "tamper_test": contains_any(ql, [
            "tamper", "tampering", "modify one character",
            "modify one byte", "change one character",
            "integrity failed", "alter ciphertext"
        ]),

        "encrypt_key": contains_any(ql, [
            "encrypt the aes key", "encrypt aes key",
            "protect the aes key", "encrypted key"
        ]),

        "authorization_code": contains_any(ql, [
            "authorization code", "authorisation code",
            "access code"
        ]),

        "audit_report": contains_any(ql, [
            "audit report", "compliance report",
            "verification report", "generate report"
        ]),
    }

    return intents


# ============================================================
# ROLE EXTRACTION
# ============================================================

KNOWN_NON_ROLES = {
    "task", "requirements", "requirement", "application", "system",
    "algorithms", "algorithm", "output", "input", "steps",
    "sender side", "receiver side", "specifications", "specification"
}


def extract_role_sections(question):
    """
    Finds headings such as:
        Doctor:
        Nurse:
        Admin:
        CLIENT:
        Compliance Officer:

    Also accepts lines in ALL CAPS without colon.
    """
    lines = question.splitlines()
    sections = {}
    current = None

    for raw in lines:
        line = raw.strip()

        if not line:
            continue

        # Heading ending in colon, reasonably short
        m = re.match(r"^([A-Za-z][A-Za-z /_-]{1,35}):\s*$", line)

        # Or an ALL-CAPS heading
        all_caps_heading = (
            len(line) <= 35
            and line.upper() == line
            and re.search(r"[A-Z]", line)
            and not re.search(r"[.!?]", line)
        )

        candidate = None

        if m:
            candidate = m.group(1).strip()
        elif all_caps_heading:
            candidate = line.strip()

        if candidate:
            low = candidate.lower()

            # Avoid treating algorithm names or common labels as roles
            algorithm_words = {
                "aes", "des", "rsa", "elgamal", "sha", "sha-256",
                "md5", "cbc", "task", "output", "input"
            }

            if (
                low not in KNOWN_NON_ROLES
                and low not in algorithm_words
                and not low.startswith("detected")
            ):
                current = candidate.title()
                sections[current] = []
                continue

        if current:
            sections[current].append(line)

    return {k: "\n".join(v) for k, v in sections.items() if v}


# ============================================================
# ROLE PERMISSION ANALYSIS
# ============================================================

def analyze_role(role_text):
    t = normalize(role_text)

    abilities = []
    restrictions = []

    if contains_any(t, ["enter", "provide", "create", "upload", "read a medical record"]):
        abilities.append("provide/create input data")

    if contains_any(t, ["encrypt", "encryption"]):
        abilities.append("encrypt data")

    if contains_any(t, ["decrypt", "decryption", "recover plaintext"]):
        abilities.append("decrypt data")

    if contains_any(t, ["hash", "sha-256", "integrity"]):
        abilities.append("compute/verify hash")

    if contains_any(t, ["sign", "digital signature"]):
        abilities.append("create/verify signature")

    if contains_any(t, ["view", "display", "access stored"]):
        abilities.append("view permitted records/metadata")

    if contains_any(t, ["store", "save", "write"]):
        abilities.append("store records/results")

    if contains_any(t, ["audit", "compliance report", "verification report"]):
        abilities.append("audit/generate report")

    if contains_any(t, [
        "must not decrypt", "cannot decrypt", "not allowed to decrypt",
        "must not be allowed to decrypt"
    ]):
        restrictions.append("MUST NOT decrypt plaintext")

    if contains_any(t, [
        "must not view plaintext", "cannot view plaintext",
        "must not access plaintext", "must not access the plaintext",
        "must not be allowed to view the plaintext"
    ]):
        restrictions.append("MUST NOT view plaintext")

    if contains_any(t, [
        "must not have access to the private key",
        "cannot access private key",
        "must not have access to doctor's private key",
        "must not have access to the doctor's private key"
    ]):
        restrictions.append("MUST NOT access private key")

    if contains_any(t, [
        "only if", "only when", "if verification successful",
        "if verification is successful", "if both pass",
        "if both are valid"
    ]):
        restrictions.append("Decrypt/display plaintext ONLY after successful verification")

    return abilities, restrictions


# ============================================================
# CRYPTO FUNCTION SUGGESTIONS
# ============================================================

def suggest_functions(algorithms, intents, modes):
    funcs = []

    if "AES" in algorithms:
        funcs += [
            "aes_encrypt(data, key, iv)",
            "aes_decrypt(ciphertext, key, iv)"
        ]

    if "DES" in algorithms:
        funcs += [
            "des_encrypt(data, key, iv)",
            "des_decrypt(ciphertext, key, iv)"
        ]

    if "RSA" in algorithms:
        if intents["encrypt_plaintext"] or intents["encrypt_key"]:
            funcs += [
                "rsa_encrypt(data, public_key)",
                "rsa_decrypt(ciphertext, private_key)"
            ]

        if intents["sign"] or intents["verify_signature"]:
            funcs += [
                "rsa_sign(hash_bytes, private_key)",
                "rsa_verify(hash_bytes, signature, public_key)"
            ]

        funcs.append("generate_rsa_keys()")

    if "ElGamal" in algorithms:
        if intents["authorization_code"] or intents["encrypt_plaintext"]:
            funcs += [
                "elgamal_encrypt(message, public_key)",
                "elgamal_decrypt(ciphertext, private_key)"
            ]

        if intents["sign"] or intents["verify_signature"]:
            funcs += [
                "elgamal_sign(hash_value, private_key)",
                "elgamal_verify(hash_value, signature, public_key)"
            ]

        funcs.append("elgamal_keygen()")

    if any(a in algorithms for a in ["SHA-256", "SHA-1", "MD5"]) or intents["hash_data"]:
        funcs.append("hash_data(data)")

    if intents["file_input"]:
        funcs.append("read_file(filename)")

    if intents["file_storage"]:
        funcs += [
            "save_record(record)",
            "load_records()"
        ]

    if intents["tamper_test"]:
        funcs.append("tamper_ciphertext(ciphertext)")

    # Remove duplicates preserving order
    out = []
    for f in funcs:
        if f not in out:
            out.append(f)

    return out


# ============================================================
# BUILD GENERIC FLOW
# ============================================================

def build_flow(algorithms, intents, modes):
    steps = []

    if intents["file_input"]:
        steps.append("Read/create the plaintext input or file.")

    if "AES" in algorithms:
        if "IV required" in modes or "CBC mode" in modes:
            steps.append("Obtain/generate AES key and IV.")
        else:
            steps.append("Obtain/generate AES key.")

        steps.append("Encrypt the actual plaintext/file using AES.")

    elif "DES" in algorithms:
        if "IV required" in modes or "CBC mode" in modes:
            steps.append("Obtain/generate DES key and IV.")
        else:
            steps.append("Obtain/generate DES key.")

        steps.append("Encrypt the actual plaintext using DES.")

    elif "RSA" in algorithms and intents["encrypt_plaintext"]:
        steps.append("Generate/load RSA public-private key pair.")
        steps.append("Encrypt the plaintext using the RSA public key.")

    if intents["encrypt_key"] and "RSA" in algorithms:
        steps.append("Encrypt/wrap the symmetric AES/DES key using the RSA public key.")

    if intents["authorization_code"] and "ElGamal" in algorithms:
        steps.append("Encrypt the authorization/access code using ElGamal.")

    if intents["hash_data"]:
        steps.append("Compute hash of the ENCRYPTED data/ciphertext.")

    if intents["sign"]:
        if "RSA" in algorithms:
            steps.append("Digitally sign the hash using the RSA private key.")
        elif "ElGamal" in algorithms:
            steps.append("Digitally sign the hash using the ElGamal private key.")
        else:
            steps.append("Digitally sign the hash using the specified private key.")

    if intents["timestamp"]:
        steps.append("Generate and store a timestamp.")

    if intents["file_storage"]:
        steps.append("Store ciphertext plus required metadata (hash/signature/IV/timestamp/etc.).")

    if intents["verify_hash"]:
        steps.append("Receiver/auditor recomputes the hash and compares it with the stored hash.")

    if intents["verify_signature"]:
        steps.append("Verify the signature using the sender's PUBLIC key.")

    if intents["tamper_test"]:
        steps.append("Tamper with one ciphertext byte/character and recompute the hash to show integrity failure.")

    if intents["decrypt_plaintext"]:
        steps.append("Only after required checks pass, decrypt using the correct key/IV.")

    if intents["audit_report"]:
        steps.append("Record verification result and generate the requested audit/compliance report.")

    return steps


# ============================================================
# EXAM RULES / COMMON CRYPTO LOGIC
# ============================================================

def print_crypto_rules(algorithms, modes, intents):
    title("IMPORTANT EXAM RULES")

    print("1. Public-key encryption:")
    print("   public key  -> encrypt")
    print("   private key -> decrypt")

    print("\n2. Digital signature:")
    print("   private key -> sign")
    print("   public key  -> verify")

    if intents["hash_data"]:
        print("\n3. If the question says integrity of encrypted data:")
        print("   hash the CIPHERTEXT, not the plaintext.")

    if "CBC mode" in modes:
        print("\n4. CBC mode requires an IV.")

    if "DES" in algorithms and "CBC mode" in modes:
        print("   DES block size = 8 bytes.")

    if "AES" in algorithms:
        print("\n5. AES key sizes are 16/24/32 bytes for AES-128/192/256.")

    if intents["verify_hash"] and intents["decrypt_plaintext"]:
        print("\n6. If question says verify before access:")
        print("   DO NOT decrypt until integrity/authenticity checks succeed.")

    if intents["tamper_test"]:
        print("\n7. Tampering demo:")
        print("   keep original hash -> modify ciphertext -> recompute hash -> mismatch -> stop decryption.")


# ============================================================
# MAIN ANALYZER
# ============================================================

def analyze_question(question):
    algorithms = detect_algorithms(question)
    modes = detect_modes(question)
    intents = detect_intents(question)
    roles = extract_role_sections(question)

    title("QUESTION ANALYSIS")

    print("Detected algorithms:")
    if algorithms:
        for a in algorithms:
            print("  -", a)
    else:
        print("  - No algorithm name detected. Read the question manually.")

    print("\nDetected crypto details:")
    if modes:
        for d in modes:
            print("  -", d)
    else:
        print("  - None explicitly detected")

    title("DETECTED REQUIREMENTS")

    labels = {
        "encrypt_plaintext": "Encrypt plaintext/file",
        "decrypt_plaintext": "Decrypt/recover plaintext",
        "hash_data": "Hash / integrity checking",
        "sign": "Create digital signature",
        "verify_signature": "Verify authenticity/signature",
        "verify_hash": "Recompute/compare hash",
        "encrypt_key": "Encrypt/wrap symmetric key",
        "authorization_code": "Protect authorization code",
        "file_input": "Read/create files",
        "file_storage": "Store encrypted record/metadata",
        "timestamp": "Timestamp",
        "rbac": "Role-Based Access Control",
        "menu": "Menu-driven program",
        "tamper_test": "Tampering / integrity-failure demo",
        "audit_report": "Audit/compliance report",
    }

    for key, label in labels.items():
        if intents.get(key):
            print("  [YES]", label)

    if roles:
        title("ROLE ANALYSIS")

        for role, text in roles.items():
            abilities, restrictions = analyze_role(text)

            print(f"\n{role}")
            print("-" * len(role))

            if abilities:
                print("Can:")
                for x in abilities:
                    print("  -", x)

            if restrictions:
                print("Restrictions:")
                for x in restrictions:
                    print("  -", x)

    title("LIKELY IMPLEMENTATION FLOW")

    flow = build_flow(algorithms, intents, modes)

    if flow:
        for i, step in enumerate(flow, 1):
            print(f"{i}. {step}")
    else:
        print("Could not infer enough steps automatically.")

    title("FUNCTIONS YOU SHOULD LOOK FOR IN YOUR MASTER FILE")

    funcs = suggest_functions(algorithms, intents, modes)

    if funcs:
        for f in funcs:
            print("  -", f)
    else:
        print("  - No function suggestions detected.")

    title("WHAT DATA SHOULD PROBABLY BE STORED")

    store_items = []

    if intents["encrypt_plaintext"]:
        store_items.append("ciphertext")

    if "IV required" in modes or "CBC mode" in modes:
        store_items.append("IV")

    if intents["hash_data"]:
        store_items.append("hash")

    if intents["sign"]:
        store_items.append("digital signature")

    if intents["timestamp"]:
        store_items.append("timestamp")

    if intents["encrypt_key"]:
        store_items.append("encrypted AES/DES key")

    if intents["authorization_code"]:
        store_items.append("encrypted authorization code")

    if store_items:
        for x in store_items:
            print("  -", x)
    else:
        print("  - Read the question for required metadata.")

    print_crypto_rules(algorithms, modes, intents)


# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 72)
    print("IS LAB EXAM HELPER v2 - GENERIC QUESTION ANALYZER")
    print("=" * 72)
    print("Paste ANY similar IS lab question.")
    print("Exact wording/scenario name does NOT need to match.")
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
