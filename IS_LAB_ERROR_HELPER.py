# IS LAB ERROR HELPER
# Offline rule-based checker for common Information Security lab coding mistakes.
# Run: python IS_LAB_ERROR_HELPER.py
# Paste the traceback/error, then the relevant code.
# Type END on a new line after each section.
# This does NOT execute your code.

import re


def read_multiline(title):
    print("\n" + title)
    print("Type END on a new line when finished.\n")

    lines = []

    while True:
        line = input()

        if line.strip() == "END":
            break

        lines.append(line)

    return "\n".join(lines)


def add_issue(issues, title, reason, correction):
    issues.append({
        "title": title,
        "reason": reason,
        "correction": correction
    })


def analyze_error(error_text, code):
    issues = []

    low_error = error_text.lower()
    low_code = code.lower()

    if "object supporting the buffer api required" in low_error:
        add_issue(
            issues,
            "SHA/hash received something that is not bytes",
            "hashlib.sha256() needs bytes. You may have passed a tuple, list, function, or other object.",
            """Check:
print(type(variable))

AES/DES:
encrypted, iv = aes_cbc_encrypt(...)
hashvalue = sha256_hex(encrypted)

RSA long:
encrypted_chunks = rsa_encrypt_long_message(...)
encrypted_bytes = b"".join(encrypted_chunks)
hashvalue = sha256_hex(encrypted_bytes)"""
        )

    if "unicode-objects must be encoded before hashing" in low_error:
        add_issue(
            issues,
            "String passed directly to hashlib",
            "hashlib expects bytes.",
            """Use:
hashlib.sha256(text.encode()).hexdigest()

or use sha256_hex() if it already converts strings."""
        )

    if "write() argument must be str" in low_error:
        add_issue(
            issues,
            "Trying to write bytes using text mode",
            "You probably opened the file with 'w' but encrypted data is bytes.",
            """Use:
with open("encrypted.bin", "wb") as file:
    file.write(encrypted)"""
        )

    if "a bytes-like object is required, not 'str'" in low_error:
        add_issue(
            issues,
            "Trying to use text where bytes are expected",
            "Binary crypto data normally needs bytes.",
            """Use rb/wb for ciphertext, keys, IVs and signatures.
Use r/w for normal text.

text.encode() -> bytes
data.decode() -> string"""
        )

    if "incorrect aes key length" in low_error:
        add_issue(
            issues,
            "Wrong AES key length",
            "AES accepts only 16, 24, or 32 byte keys. You may also be passing ciphertext instead of the AES key.",
            """AES-128:
aes_key = get_random_bytes(16)

Hybrid encryption:
encrypt_aes_key = rsa_encrypt_bytes(aes_key, public_key)

NOT:
encrypt_aes_key = rsa_encrypt_bytes(encrypted, public_key)"""
        )

    if "data must be padded to 16 byte boundary" in low_error:
        add_issue(
            issues,
            "AES CBC data is not padded",
            "AES CBC requires block-sized input.",
            """Encryption:
cipher.encrypt(pad(data, AES.block_size))

Decryption:
unpad(cipher.decrypt(ciphertext), AES.block_size)"""
        )

    if "padding is incorrect" in low_error or "pkcs#7 padding is incorrect" in low_error:
        add_issue(
            issues,
            "AES/DES decryption used wrong key, IV, or damaged ciphertext",
            "Padding errors usually happen after decrypting with incorrect crypto inputs.",
            """Check:
1. same key
2. same IV
3. original ciphertext

If integrity failed, do NOT decrypt tampered ciphertext."""
        )

    if "incorrect des key length" in low_error:
        add_issue(
            issues,
            "Wrong DES key length",
            "DES requires exactly 8 bytes.",
            """Use:
des_key = get_random_bytes(8)"""
        )

    if "plaintext is too long" in low_error or "plain text is too long" in low_error:
        add_issue(
            issues,
            "RSA plaintext is too large",
            "RSA-OAEP can encrypt only a small message directly.",
            """Small record:
rsa_encrypt_bytes(...)

Long message:
rsa_encrypt_long_message(...)

Large file:
AES encrypt the file
RSA encrypt ONLY the AES key"""
        )

    if "ciphertext with incorrect length" in low_error:
        add_issue(
            issues,
            "RSA ciphertext has wrong shape/length",
            "You may be passing joined chunks or non-RSA data to rsa_decrypt_bytes().",
            """rsa_decrypt_bytes() expects one RSA ciphertext block.

rsa_decrypt_long_message() expects the original LIST of RSA chunks."""
        )

    if "int' object is not iterable" in low_error or '"int" object is not iterable' in low_error:
        if "elgamal_encrypt_text" in low_code:
            add_issue(
                issues,
                "Integer passed to ElGamal text encryption",
                "elgamal_encrypt_text() loops through characters, so it needs a string.",
                """Integer code:
code_encrypted = elgamal_encrypt_int(1234, public_key)

Text code:
code_encrypted = elgamal_encrypt_text("AUTH1234", public_key)"""
            )

    if "not enough values to unpack" in low_error or "too many values to unpack" in low_error:
        add_issue(
            issues,
            "Wrong assumption about function return values",
            "Look at the function's return line.",
            """return ciphertext, iv
-> encrypted, iv = function(...)

return ciphertext
-> encrypted = function(...)

return [...]
-> result is a list"""
        )

    if "nameerror" in low_error:
        name_match = re.search(r"name ['\"]([^'\"]+)['\"] is not defined", error_text, re.I)
        bad_name = name_match.group(1) if name_match else "the variable"

        add_issue(
            issues,
            f"{bad_name} was used before being created",
            "This usually means a typo, wrong variable name, or the variable was created only inside an if-block.",
            f"""Search every use of:
{bad_name}

Make sure it is assigned before use and spelling is identical."""
        )

    if "unboundlocalerror" in low_error:
        add_issue(
            issues,
            "Variable exists only on some paths",
            "A variable was assigned only inside a condition and later used outside it.",
            """Move dependent code inside the same successful condition,
or initialize the variable before the condition."""
        )

    if re.search(r'rsa_encrypt_bytes\s*\(\s*encrypted\s*,', code):
        add_issue(
            issues,
            "Possible RSA/AES hybrid mistake",
            "Your RSA call appears to encrypt the AES ciphertext.",
            """If the requirement is 'RSA encrypt the AES key':
encrypt_aes_key = rsa_encrypt_bytes(aes_key, hpub)"""
        )

    if re.search(r'\w+\s*,\s*iv\s*=\s*rsa_encrypt', code, re.I):
        add_issue(
            issues,
            "RSA incorrectly treated like AES/DES",
            "RSA encryption does not return an IV.",
            """Use:
encrypted = rsa_encrypt_bytes(...)

AES/DES commonly return:
encrypted, iv = ..."""
        )

    calls = re.findall(r'elgamal_encrypt_text\s*\(\s*([A-Za-z_]\w*)\s*,', code)

    for var in calls:
        if re.search(rf'\b{re.escape(var)}\s*=\s*\d+\b', code):
            add_issue(
                issues,
                "ElGamal text helper is receiving an integer",
                f"{var} appears to be numeric.",
                f"""Use:
elgamal_encrypt_int({var}, public_key)

or make it a string if the question treats it as text."""
            )
            break

    if "rsa_encrypt_long_message" in code and re.search(
        r'sha256_hex\s*\(\s*(?:encrypt|encrypted_chunks)\s*\)', code
    ):
        add_issue(
            issues,
            "Possible hashing of RSA chunk list",
            "rsa_encrypt_long_message() returns a list.",
            """Use:
encrypted_chunks = rsa_encrypt_long_message(...)
encrypted_bytes = b"".join(encrypted_chunks)
hashvalue = sha256_hex(encrypted_bytes)"""
        )

    if re.search(r'with\s+open\([^)]*,\s*["\']w["\']\s*\)', code, re.I):
        if (
            "file.write(encrypted" in low_code
            or "file.write(iv +" in low_code
            or "file.write(signature" in low_code
        ):
            add_issue(
                issues,
                "Possible binary file opened in text mode",
                "Ciphertext, IVs, encrypted keys and signatures are bytes.",
                """Use "wb" to write them and "rb" to read them."""
            )

    if "aes_cbc_encrypt" in code and re.search(r'\[\s*:16\s*\]', code):
        if "iv + encrypted" not in code:
            add_issue(
                issues,
                "IV may not have been stored with AES ciphertext",
                "Receiver code appears to expect the first 16 bytes to be the IV.",
                """Store:
file.write(iv + encrypted)

Read:
received_iv = data[:16]
received_encrypted = data[16:]"""
            )

    if not issues:
        add_issue(
            issues,
            "No exact rule matched",
            "This helper only knows common lab mistakes; it is not an AI debugger.",
            """Check:
1. print(type(variable))
2. inspect function return line
3. bytes vs string
4. rb/wb vs r/w
5. key size
6. public/private key
7. same IV
8. exact variable names

Then paste the smallest failing block and traceback into ChatGPT."""
        )

    return issues


def print_report(issues):
    print("\n" + "=" * 65)
    print("POSSIBLE ERROR REPORT")
    print("=" * 65)

    for number, issue in enumerate(issues, 1):
        print(f"\n{number}. {issue['title']}")
        print("-" * 65)
        print("WHY:")
        print(issue["reason"])
        print("\nCORRECTION:")
        print(issue["correction"])

    print("\n" + "=" * 65)


def quick_reference():
    print("""
QUICK REFERENCE

AES:
    encrypted, iv = aes_cbc_encrypt(data, aes_key)
    AES-128 key = get_random_bytes(16)
    IV = 16 bytes

DES:
    encrypted, iv = des_encrypt(data, des_key)
    DES key = get_random_bytes(8)
    IV = 8 bytes

RSA small:
    encrypted = rsa_encrypt_bytes(data, public_key)
    decrypted = rsa_decrypt_bytes(encrypted, private_key)

RSA long:
    chunks = rsa_encrypt_long_message(data, public_key)
    encrypted_bytes = b"".join(chunks)
    decrypted = rsa_decrypt_long_message(chunks, private_key)

Hybrid:
    file/data -> AES
    AES key -> RSA public key

Hash:
    SHA256 needs bytes/string helper
    Do not directly hash list/tuple

ElGamal:
    integer -> elgamal_encrypt_int()
    text -> elgamal_encrypt_text()

Files:
    text -> r / w
    crypto bytes -> rb / wb
""")


def main():
    while True:
        print("\nIS LAB ERROR HELPER")
        print("1. Check error + code")
        print("2. Quick reference")
        print("0. Exit")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            error_text = read_multiline("PASTE ERROR / TRACEBACK")
            code = read_multiline("PASTE RELEVANT CODE")

            issues = analyze_error(error_text, code)

            print_report(issues)

        elif choice == "2":
            quick_reference()

        elif choice == "0":
            break

        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()
