"""Read a loosely written IS lab question and print an exam coding plan.

Usage on Windows, with this file beside IS_Exam_Toolkit_Labs_1_to_8.py:
    py Question_To_Code_Exam_Coach.py
    py Question_To_Code_Exam_Coach.py --question-file question.txt
    py Question_To_Code_Exam_Coach.py --save-plan answer_plan.txt

Paste the question, then type END on its own line. This uses Python's standard library only.
It reads toolkit source with ast; it never executes the toolkit or submits an answer.
"""
from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLKIT_NAMES = ("IS_Exam_Toolkit_Labs_1_to_8.py", "IS_Exam_Toolkit_Labs_1_to_8 (1).py")

# Every name below is checked against the chosen toolkit before being recommended.
PATTERNS = (
    (r"\b(?:caesar|additive|shift cipher)\b", "Lab 1 — Caesar/additive", ("additive_encrypt", "additive_decrypt")),
    (r"\bmultiplicative cipher\b", "Lab 1 — multiplicative", ("multiplicative_encrypt", "multiplicative_decrypt")),
    (r"\baffine\b", "Lab 1 — affine", ("affine_encrypt", "affine_decrypt")),
    (r"\bvigen[eè]re\b", "Lab 1 — Vigenère", ("vigenere_encrypt", "vigenere_decrypt")),
    (r"\bauto[ -]?key\b", "Lab 1 — autokey", ("autokey_encrypt", "autokey_decrypt")),
    (r"\bplayfair\b", "Lab 1 — Playfair", ("playfair_encrypt", "playfair_decrypt")),
    (r"\bhill(?: cipher)?\b", "Lab 1 — Hill", ("hill_encrypt_2x2", "hill_decrypt_2x2")),
    (r"\b(?:brute[ -]?force|known[ -]?plaintext)\b", "Lab 1 — attack", ("additive_bruteforce", "affine_keys_from_known_pair")),
    (r"\baes\b|aes[ -]?(?:128|192|256)\b", "Lab 2 — AES", ("aes_cbc_encrypt", "aes_cbc_decrypt")),
    (r"\b(?:3des|triple[ -]?des)\b", "Lab 2 — 3DES", ("triple_des_encrypt", "triple_des_decrypt")),
    (r"(?<!3)\bdes\b(?!3)", "Lab 2 — DES", ("des_encrypt", "des_decrypt")),
    (r"\bdiffie[ -]?hellman\b|\b(?:dh|ecdh)\b", "Lab 3 — key agreement", ("dh_generate_public", "dh_shared_secret")),
    (r"\b(?:ecc|elliptic curve|secp256r1)\b", "Lab 3 — ECC hybrid", ("ecc_hybrid_encrypt", "ecc_hybrid_decrypt")),
    (r"\brsa\b", "Lab 3/6 — RSA (check whether it encrypts a key or signs data)", ()),
    (r"\bel[ -]?gamal\b", "Lab 3/6/7 — ElGamal (encryption, signature or product?)", ()),
    (r"\brabin\b", "Lab 4 — Rabin", ("rabin_encrypt_int", "rabin_decrypt_roots")),
    (r"\b(?:schnorr)\b", "Lab 6 — Schnorr signatures", ("schnorr_sign", "schnorr_verify")),
    (r"\bpaillier\b|\bhomomorph(?:ic|ically)?\b.{0,35}\b(?:add|sum|aggregate|tally)", "Lab 7 — encrypted addition", ("paillier_keygen", "paillier_encrypt", "paillier_add", "paillier_decrypt")),
    (r"\b(?:searchable encryption|encrypted index|inverted index|\bsse\b|\bpkse\b)\b", "Lab 8 — encrypted search", ("search_token", "searchable_find", "sse_build_inverted")),
)
ROLES = ("Researcher", "Reviewer", "Finance Officer", "Finance", "Voter", "Client", "Server", "Election Commission", "Auditor", "Administrator", "Admin", "Doctor", "Nurse", "Patient", "Sender", "Receiver", "Officer", "Student", "Faculty")
FIELDS = ("grant id", "grant description", "grant amount", "voter id", "candidate id", "candidate selection", "constituency id", "constituency", "timestamp", "document id", "patient id", "message", "file", "record id")


def read_question(path: Path | None) -> str:
    """Accept either a text file or an imperfect multiline paste ending with END."""
    if path is not None:
        return path.read_text(encoding="utf-8")
    print("Paste the entire question, even if formatting is messy. Type END on its own line:")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip().upper() == "END":
            break
        lines.append(line)
    return "\n".join(lines)


def find_toolkit(explicit: Path | None) -> Path | None:
    """Find the source file without importing or running its menu."""
    if explicit is not None:
        return explicit
    for folder in (HERE, Path.cwd(), HERE / "upload", Path.cwd() / "upload"):
        for name in TOOLKIT_NAMES:
            candidate = folder / name
            if candidate.is_file():
                return candidate
    return None


def parse_toolkit(path: Path | None) -> tuple[dict[str, ast.AST], dict[str, set[str]], str]:
    """Read callable names and their dependencies from source, not from guesses."""
    if path is None or not path.is_file():
        return {}, {}, "Toolkit was not beside this script. Put both .py files in one folder or use --toolkit."
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (OSError, SyntaxError, UnicodeError) as exc:
        return {}, {}, f"Cannot inspect toolkit source: {exc}"
    functions = {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    dependencies = {}
    for name, node in functions.items():
        dependencies[name] = {item.func.id for item in ast.walk(node)
                              if isinstance(item, ast.Call) and isinstance(item.func, ast.Name)
                              and item.func.id in functions and item.func.id != name}
    return functions, dependencies, f"Validated against {path.name} ({len(functions)} top-level functions)."


def signature(node: ast.AST) -> str:
    """Render the function's actual call shape without importing Crypto."""
    args = node.args
    names = [a.arg for a in args.posonlyargs + args.args]
    names += (["*" + args.vararg.arg] if args.vararg else [])
    names += [a.arg for a in args.kwonlyargs]
    names += (["**" + args.kwarg.arg] if args.kwarg else [])
    return f"{node.name}({', '.join(names)})"


def copy_closure(seeds: list[str], functions: dict, dependencies: dict) -> list[str]:
    """List toolkit helper definitions needed when import is forbidden."""
    seen = set()
    ordered = []
    def visit(name):
        if name in seen or name not in functions:
            return
        seen.add(name)
        for dep in sorted(dependencies.get(name, ()), key=lambda x: functions[x].lineno):
            visit(dep)
        ordered.append(name)
    for name in seeds:
        visit(name)
    return ordered


def classify(question: str) -> str:
    q = question.casefold()
    if re.search(r"\bgrant\b", q) and re.search(r"\b(?:researcher|reviewer|expense|finance)\b", q):
        return "grant"
    if re.search(r"\b(?:e[ -]?voting|ballot|voter|election)\b", q) and re.search(r"\b(?:candidate|vote|constituency|tally)\b", q):
        return "vote"
    return "generic"


def find_roles(question: str, kind: str) -> list[str]:
    """Detect actors doing work, avoiding phrases such as 'patient notes'."""
    q = question.casefold()
    found = []
    verbs = r"should\b|must\b|can\b|enters?\b|fills?\b|submits?\b|verif\w*\b|search\w*\b|computes?\b|aggregat\w*\b|casts?\b|checks?\b|decrypts?\b|encrypts?\b|receives?\b|sends?\b|views?\b|maintains?\b"
    for role in ROLES:
        role_word = r"\b" + re.escape(role.casefold()) + r"\b"
        named_action = re.search(role_word + r"(?:\s*:\s*|\s+side\b|\s+(?:" + verbs + r"))", q)
        role_list = re.search(r"\broles?\s*(?:are|:|=)\s*[^.\n]{0,130}\b" + re.escape(role.casefold()) + r"\b", q)
        if named_action or role_list:
            found.append(role)
    if kind == "grant":
        found = list(dict.fromkeys(found + ["Researcher", "Reviewer", "Finance Officer"]))
        found = [r for r in found if r != "Finance" or "Finance Officer" not in found]
    elif kind == "vote":
        found = list(dict.fromkeys(found + ["Voter", "Server", "Election Commission"]))
    return found


def analyze(question: str, functions: dict, dependencies: dict, toolkit_note: str) -> str:
    """Turn requirement verbs into an ordered answer plan, with concrete connections."""
    q = re.sub(r"\s+", " ", question.casefold())
    kind = classify(question)
    hits = [(label, list(names)) for pattern, label, names in PATTERNS if re.search(pattern, q)]
    role_hits = find_roles(question, kind)
    field_hits = [field for field in FIELDS if re.search(r"\b" + re.escape(field) + r"\b", q)]
    if kind == "grant":
        field_hits = list(dict.fromkeys(["grant id", "description", "amount"] + field_hits))
    elif kind == "vote":
        field_hits = list(dict.fromkeys(["voter id", "candidate id", "constituency id"] + field_hits))
    features = {
        "menu": bool(re.search(r"menu[ -]?driven|role[ -]?based|\brbac\b|\bmenus?\b", q)) or bool(role_hits),
        "input": bool(re.search(r"\b(?:enter\w*|input|fill\w*|submit\w*|select\w*|choose|cast)\b", q)),
        "persist": bool(re.search(r"\b(?:persist|stored|store|database|file|restart|earlier|previous|records)\b", q)),
        "hash": bool(re.search(r"\b(?:md5|sha[ -]?(?:1|256|512)|hash|integrity)\b", q)),
        "signature": bool(re.search(r"\b(?:sign|signs|signed|signature|authenticity|non[ -]?repudiation)\b", q)),
        "verify": bool(re.search(r"\b(?:verif\w*|recomput\w*|tamper\w*|integrity|authenticity)\b", q)),
        "search": bool(re.search(r"\b(?:search\w*|index\w*|quer\w*|locat\w*)\b", q)),
        "sum": bool(re.search(r"\b(?:aggregat\w*|sum\w*|total\w*|expenditure|tally\w*|count\w*)\b", q)),
        "timestamp": bool(re.search(r"\b(?:timestamp|deadline|voting period|time range)\b", q)),
        "hex": bool(re.search(r"\b(?:hexadecimal|hex dump|hexdump)\b", q)),
        "threshold": bool(re.search(r"\bthreshold\b", q)),
        "benchmark": bool(re.search(r"\b(?:performance|benchmark|measure|timing|plot)\b", q)),
    }
    aes_bits = re.findall(r"\baes[ -]?(128|192|256)\b", q)
    hashes = [name for name, pattern in (("MD5", r"\bmd5\b"), ("SHA-1", r"\bsha[ -]?1\b"),
                                       ("SHA-256", r"\bsha[ -]?256\b"), ("SHA-512", r"\bsha[ -]?512\b")) if re.search(pattern, q)]
    modes = [name for name in ("CBC", "CTR", "GCM", "ECB", "CFB", "OFB") if re.search(r"\b" + name.casefold() + r"\b", q)]
    lines = []
    def section(title):
        lines.append("\n" + title + "\n" + "-" * len(title))
    def add(*items):
        lines.extend(items)
    add("IS EXAM QUESTION → CODE PLAN", toolkit_note, "Detected pattern: " + {"grant": "secure grant portal", "vote": "e-voting", "generic": "combined/general lab question"}[kind])
    section("1. Decode the question before coding")
    add("Roles: " + (", ".join(role_hits) if role_hits else "No clear role headings; identify actors manually."))
    add("Named fields: " + (", ".join(field_hits) if field_hits else "No known field labels; underline every requested input."))
    add("Crypto: " + ("; ".join(label for label, _ in hits) if hits else "No confidently named algorithm; inspect the prompt manually."))
    add("Exact parameters: " + ", ".join(x for x in ["AES-" + "/".join(aes_bits) if aes_bits else "", "/".join(modes) + " mode" if modes else "", "/".join(hashes) if hashes else "", "RSA-4096" if re.search(r"rsa[ -]?4096", q) else ""] if x))
    add("Rubric actions: " + ", ".join(k for k, present in features.items() if present))
    section("2. Choose your starting code")
    chosen = []
    if kind == "grant":
        add("Start from grant_menu(folder). It ALREADY has Researcher, Reviewer, Finance, numbered choices, input and persistent JSON.")
        chosen += ["grant_menu", "grant_setup", "grant_submit", "grant_verify", "grant_search", "grant_aggregate"]
    elif kind == "vote":
        add("Start from vote_menu(folder). It ALREADY has Voter, Server/Auditor, Commission, input and persistence.")
        chosen += ["vote_menu", "vote_setup", "vote_cast", "vote_verify", "vote_search", "vote_tally"]
    else:
        add("Start with load_json/save_json plus a while True role menu. Adapt the matching primitive functions below.")
        chosen += ["load_json", "save_json", "choose_menu"] if features["menu"] or features["persist"] else []
    for label, names in hits:
        available = [n for n in names if n in functions]
        add(f"{label}: " + (", ".join(signature(functions[n]) for n in available) if available else ", ".join(names)))
        chosen += available
    if re.search(r"\brsa\b", q):
        rsa_names = ["rsa_encrypt_bytes", "rsa_decrypt_bytes"] if re.search(r"encrypt.{0,18}(?:aes|session|key)|wrap", q) else []
        rsa_names += ["rsa_sign_md5", "rsa_verify_md5"] if "MD5" in hashes and features["signature"] else []
        rsa_names += ["rsa_sign_sha512", "rsa_verify_sha512"] if "SHA-512" in hashes and features["signature"] and kind != "vote" else []
        rsa_names += ["rsa_sign_sha256", "rsa_verify_sha256"] if features["signature"] and not ("MD5" in hashes or "SHA-512" in hashes) else []
        for name in rsa_names:
            if name in functions:
                add("RSA task: " + signature(functions[name]))
                chosen.append(name)
        if re.search(r"\b(?:multiplicativ\w*|product|multiply)\b", q) and "rsa_textbook_multiply" in functions:
            add("RSA HOMOMORPHIC PRODUCT: rsa_textbook_multiply(c1,c2,n) works only for unpadded textbook RSA, never RSA-OAEP.")
            chosen.append("rsa_textbook_multiply")
    hash_functions = {"MD5": "md5_hex", "SHA-1": "sha1_hex", "SHA-256": "sha256_hex"}
    for hash_name in hashes:
        name = hash_functions.get(hash_name)
        if name and name in functions:
            add(f"{hash_name} integrity: " + signature(functions[name]))
            chosen.append(name)
        elif hash_name == "SHA-512":
            add("SHA-512 integrity: hashlib.sha512(exact_bytes).digest()  # standard-library hash")
    if re.search(r"\bel[ -]?gamal\b", q) and features["signature"]:
        for name in ("elgamal_sign_digest", "elgamal_verify_digest"):
            if name in functions:
                add("ElGamal signature: " + signature(functions[name]))
                chosen.append(name)
    elif re.search(r"\bel[ -]?gamal\b", q):
        eg_names = ["elgamal_encrypt_int", "elgamal_decrypt_int"]
        if re.search(r"\b(?:multiplicativ\w*|product|multiply|homomorph\w*)\b", q):
            eg_names.insert(1, "elgamal_multiply_ciphertexts")
            add("ElGamal ciphertext pairs multiply COMPONENT-WISE mod p to multiply plaintext integers.")
        for name in eg_names:
            if name in functions:
                add("ElGamal operation: " + signature(functions[name]))
                chosen.append(name)
    if features["search"] and "search_token" in functions:
        chosen += ["search_token"]
        if kind == "generic":
            for name in ("searchable_encrypt_document", "searchable_find", "searchable_decrypt_document"):
                if name in functions:
                    add("Encrypted document search: " + signature(functions[name]))
                    chosen.append(name)
    chosen = list(dict.fromkeys(chosen))
    if functions:
        missing = [n for n in chosen if n not in functions]
        if missing:
            add("MISSING FROM THIS TOOLKIT: " + ", ".join(missing) + ". Do not copy a nonexistent name.")
    section("3. Connect the data: follow this order")
    if kind == "grant":
        add("ONCE: folder=Path('exam_demo_data/grant'); folder.mkdir(...); keys=grant_setup(folder). NEVER regenerate keys on restart.",
            "RESEARCHER: input Grant ID, description, integer amount → grant_submit(folder,keys,id,description,amount).",
            "  Internally: search_token(ID) + AES-192(description) + Paillier(amount) → canonical_bytes(record) → MD5 → RSA sign → save_json.",
            "REVIEWER: grant_search(folder,keys,id) → for each row grant_verify(row,keys) → only if both True, AES-decrypt description → .encode().hex(' ').",
            "FINANCE: IDs from input → grant_aggregate(folder,keys,ids) → verify EVERY selected row → paillier_add(ciphertexts) → decrypt final ciphertext only.",
            "VIEW EARLIER: load_json(folder/'grants.json',[]) and display encrypted rows.")
    elif kind == "vote":
        add("ONCE: folder=Path('exam_demo_data/vote'); folder.mkdir(...); keys=vote_setup(folder). Reuse keys and election window.",
            "VOTER: input voter ID, constituency, candidate ID → vote_cast(folder,keys,voter_id,constituency,candidate).",
            "  Internally: canonical ballot bytes → SHA-512 → AES-256-CBC ballot → RSA-OAEP wraps AES key → ElGamal signs digest → Paillier encrypts one-hot vote bits → authenticated timestamp → save_json.",
            "SERVER: vote_verify(row,keys) checks timestamp/window, AES ballot hash and signatures; reject invalid before tally.",
            "SEARCH: vote_search(folder,keys,constituency,day) uses keyed exact tokens and returns encrypted records.",
            "COMMISSION: vote_tally(folder,keys) verifies each ballot → Paillier adds one-hot bit columns per candidate → quorum demo opens FINAL aggregates only.",
            "An encrypted sum of candidate IDs is NOT vote counts. Use one encrypted 0/1 per candidate.")
        if re.search(r"time ranges?|between.{0,30}(?:date|time)", q):
            if "vote_search_time_range" in functions:
                add("TIME RANGE: vote_search_time_range(folder,keys,start_iso,end_iso,constituency) returns verified encrypted matches.")
                chosen.append("vote_search_time_range")
            else:
                add("TIME RANGE GAP IN THIS ATTACHED TOOLKIT: vote_search only handles one UTC day. Filter its signed public timestamps after verifying the rows, or add day-bucket range lookup; do not claim exact ranges already work.")
    else:
        add("1) Decide your record fields and a stable key file. Generate keys only if the key file does not exist.",
            "2) For each role action, call input() and validate BEFORE doing crypto. Use integer units/cents for Paillier.",
            "3) Sender: exact plaintext/file bytes → required hash/encryption/signature in the order written in the question → store ciphertext + IV/nonce + hash + signature.",
            "4) Receiver: load stored row → recompute hash and verify signature → reject failures → authorized decryption/search/aggregation.",
            "5) Use search_token for exact encrypted lookups; reuse the SAME secret index key. Save after append and reload at startup.",
            "6) If Paillier is requested for a SUM, paillier_add combines ciphertexts; paillier_decrypt is called on the FINAL ciphertext.",
            "7) Print every rubric result, including invalid input and tampered-record rejection.")
        add("CONNECTING EXAMPLES (adapt field names and order to the question):")
        if any("AES" in label for label, _ in hits):
            add("  aes_key = get_random_bytes(24)  # use 16/24/32 bytes for AES-128/192/256",
                "  ciphertext, iv = aes_cbc_encrypt(plaintext, aes_key)  # store BOTH",
                "  recovered = aes_cbc_decrypt(ciphertext, aes_key, iv)")
        if features["hash"]:
            add("  original = canonical_bytes(body)  # same record fields and serialization on both sides",
                "  stored_hash = hashlib.sha256(original).hexdigest()  # change to required hash",
                "  integrity_ok = (hashlib.sha256(canonical_bytes(received_body)).hexdigest() == stored_hash)")
        if re.search(r"\brsa\b", q) and features["signature"]:
            add("  signature = rsa_sign_sha256(original, sender_private)  # choose requested hash variant",
                "  valid = rsa_verify_sha256(canonical_bytes(received_body), signature, sender_public)")
        if any("encrypted addition" in label for label, _ in hits):
            add("  public, private = paillier_keygen()  # generate once; preserve same key for every record",
                "  encrypted_amounts = [paillier_encrypt(int(x), public) for x in amounts]",
                "  encrypted_total = paillier_add(encrypted_amounts, public)",
                "  final_total = paillier_decrypt(encrypted_total, public, private)  # not individual values")
    section("4. Menu and code skeleton")
    module = "IS_Exam_Toolkit_Labs_1_to_8"
    add("Place the toolkit beside your answer file and name it IS_Exam_Toolkit_Labs_1_to_8.py; a filename containing ' (1)' needs renaming before normal import.")
    if kind == "grant":
        add("from pathlib import Path", f"from {module} import grant_menu", "grant_menu(Path('exam_demo_data/grant'))  # Complete menu; edit action fields if question differs.")
    elif kind == "vote":
        add("from pathlib import Path", f"from {module} import vote_menu", "vote_menu(Path('exam_demo_data/vote'))  # Complete menu; edit candidates and time window if required.")
    else:
        roles = role_hits[:4] or ["Sender", "Receiver"]
        add("from pathlib import Path", f"from {module} import load_json, save_json", "folder = Path('exam_data'); folder.mkdir(exist_ok=True)",
            "records = load_json(folder / 'records.json', [])", "while True:",
            "    print(" + repr(" | ".join(f"{i} {role}" for i, role in enumerate(roles, 1)) + " | 0 Exit") + ")",
            "    role = input('Choose role: ').strip()", "    if role == '0': break")
        for i, role in enumerate(roles, 1):
            add(f"    {'if' if i == 1 else 'elif'} role == '{i}':",
                "        while True:",
                f"            print('1 {role} action | 0 Back')  # Replace action text from question",
                "            action = input('Action: ').strip()",
                "            if action == '0': break",
                "            elif action == '1':",
                f"                print('TODO: {role} — take required input, call selected toolkit functions, print output')",
                "            else: print('Invalid option')")
        add("    else: print('Invalid role')", "# Save after each successful submission: records.append(row); save_json(folder/'records.json', records)")
    section("5. If copying functions instead of importing")
    if functions:
        closure = copy_closure(chosen, functions, dependencies)
        if kind in ("grant", "vote"):
            closure = copy_closure(["grant_menu" if kind == "grant" else "vote_menu"], functions, dependencies)
        add("Copy these named definitions in dependency order (plus their import lines at the top of the toolkit):")
        add(", ".join(closure) if closure else "No toolkit functions confidently identified.")
        add("Do not copy only grant_menu/vote_menu: those call many helper functions. Importing the full toolkit is simpler if allowed.")
    else:
        add("Place the toolkit beside this coach to validate signatures and list its dependencies.")
    section("6. Last checks before submission")
    add("[ ] A menu appears when the ANSWER file runs; role actions are reachable and 0 exits.",
        "[ ] Every requested field is collected with input() and every action prints a result.",
        "[ ] Keys and records persist across a second run; save IV/nonce and signatures with ciphertext.",
        "[ ] Verification fails on a changed record and invalid rows never enter the total.",
        "[ ] Required algorithm sizes/modes, time checks, exact search, and hex output match the question.")
    if features["threshold"]:
        add("LIMIT: this toolkit's two-of-three Shamir key reconstruction is a classroom quorum demo, not full threshold Paillier partial decryption with proofs.")
    if "PKSE" in question.upper():
        add("LIMIT: Paillier encryption is randomized; re-encrypting a search word will not give an equal ciphertext. Toolkit uses a separate keyed token for lookup.")
    if re.search(r"\b(?:gnupg|snort)\b", q):
        add("LIMIT: GnuPG/Snort exercises need installed command-line tools; a Python cipher function cannot replace them.")
    if not hits and kind == "generic":
        add("LOW CONFIDENCE: no exact primitive matched. Underline algorithm names and conditions in the prompt before coding.")
    return "\n".join(lines).strip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Explain how to assemble an IS lab answer from the toolkit")
    parser.add_argument("--question-file", type=Path, help="Read question from a UTF-8 text file instead of pasting it")
    parser.add_argument("--toolkit", type=Path, help="Path to the labs 1–8 Python toolkit")
    parser.add_argument("--save-plan", type=Path, help="Also save the printed plan as a UTF-8 text file")
    args = parser.parse_args()
    try:
        question = read_question(args.question_file)
        if not question.strip():
            print("No question supplied. Paste it, then type END on its own line.")
            return 1
        functions, dependencies, note = parse_toolkit(find_toolkit(args.toolkit))
        plan = analyze(question, functions, dependencies, note)
        print(plan)
        if args.save_plan:
            args.save_plan.write_text(plan, encoding="utf-8")
            print(f"Saved plan: {args.save_plan}")
        return 0
    except (OSError, UnicodeError) as exc:
        print(f"Cannot read or save the file: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
