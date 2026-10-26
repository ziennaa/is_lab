# SECURE GRANT EXPENSE PORTAL — comments explain each line of the menu.
# Lab demonstration: MD5 and plaintext private-key storage are NOT production-safe.
import json
import math
import hashlib
import secrets
import hmac
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import MD5
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime

# YOUR EXISTING TOOLKIT HELPERS — KEEP THESE ABOVE THE MENU.
def aes_cbc_encrypt(plaintext, key, iv=None):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    if iv is None:
        iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, AES.block_size)), iv

def aes_cbc_decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

def paillier_keygen(bits=1024):
    if bits < 512 or bits % 2:
        raise ValueError("Use an even Paillier modulus size of at least 512 bits.")
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    while q == p:
        q = getPrime(bits // 2)
    n = p * q
    lam = math.lcm(p - 1, q - 1)
    g = n + 1
    mu = pow((pow(g, lam, n * n) - 1) // n, -1, n)
    return {"n": n, "g": g}, {"lambda": lam, "mu": mu}

def paillier_encrypt(amount, public):
    n = int(public["n"])
    if not isinstance(amount, int) or not 0 <= amount < n:
        raise ValueError("Paillier amount must be an integer between 0 and n-1.")
    r = secrets.randbelow(n - 1) + 1
    while math.gcd(r, n) != 1:
        r = secrets.randbelow(n - 1) + 1
    return (pow(int(public["g"]), amount, n * n) * pow(r, n, n * n)) % (n * n)

def paillier_add(ciphertexts, public):
    n2 = int(public["n"]) ** 2
    result = 1
    for item in ciphertexts:
        c = int(item)
        if not 0 < c < n2 or math.gcd(c, n2) != 1:
            raise ValueError("Invalid Paillier ciphertext")
        result = result * c % n2
    return result

def paillier_decrypt(ciphertext, public, private):
    n = int(public["n"])
    c = int(ciphertext)
    if not 0 < c < n * n or math.gcd(c, n * n) != 1:
        raise ValueError("Invalid Paillier ciphertext")
    return ((pow(c, int(private["lambda"]), n * n) - 1) // n) * int(private["mu"]) % n

def md5_hex(data):
    return hashlib.md5(data.encode() if isinstance(data, str) else data).hexdigest()

def rsa_sign_md5(data, private_key):
    return pkcs1_15.new(private_key).sign(MD5.new(data))

def rsa_verify_md5(data, signature, public_key):
    try:
        pkcs1_15.new(public_key).verify(MD5.new(data), signature)
        return True
    except (ValueError, TypeError):
        return False

def rsa_generate(bits=2048):
    private = RSA.generate(bits)
    return private.publickey(), private

def search_token(value, index_key):
    normalized = " ".join(str(value).casefold().split())
    return hmac.new(index_key, normalized.encode(), hashlib.sha256).hexdigest()

def load_json(path, default=None):
    if not Path(path).exists():
        return default
    return json.loads(Path(path).read_text(encoding="utf-8"))

def save_json(path, value):
    target = Path(path)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    temporary.replace(target)

# ================= FILE + KEY SETUP (RUNS BEFORE MENU) =================
DATA = Path("grant_records.json")  # File containing previously submitted encrypted grants.
KEYS = Path("grant_keys.json")      # File holding keys so old grants can still be opened after restart.

if not KEYS.exists():                                     # Only generate keys if this is the first run.
    rsa_pub, rsa_priv = rsa_generate(2048)               # Make a matching RSA key pair for signatures.
    aes_key = get_random_bytes(24)                       # 24 bytes = AES-192 key.
    ppub, ppriv = paillier_keygen(1024)                   # Generate Paillier public and private keys.
    index_key = get_random_bytes(32)                     # Secret key for creating searchable ID tokens.
    save_json(KEYS, {                                    # Save these keys for future program restarts.
        "rsa": rsa_priv.export_key().decode(),          # RSA object -> text JSON can store.
        "aes": aes_key.hex(),                           # AES bytes -> hex string.
        "ppub": ppub,                                   # Paillier public key dictionary.
        "ppriv": ppriv,                                 # Paillier private key dictionary.
        "index": index_key.hex()                        # Index key bytes -> hex string.
    })                                                  # End keys dictionary and save call.

keys = load_json(KEYS)                                   # Read key information from the saved JSON file.
rsa_priv = RSA.import_key(keys["rsa"])                  # Recreate RSA private-key object from saved text.
rsa_pub = rsa_priv.publickey()                           # Recover the matching RSA public key.
aes_key = bytes.fromhex(keys["aes"])                    # Convert saved AES key hex back to bytes.
index_key = bytes.fromhex(keys["index"])                # Convert saved search key hex back to bytes.
ppub = keys["ppub"]                                     # Load Paillier public key dictionary.
ppriv = keys["ppriv"]                                   # Load Paillier private key dictionary.
records = load_json(DATA, [])                            # Load old grants, or [] if no record file exists.

# ================= MAIN ROLE MENU =================
while True:                                              # Show the main menu until the user exits.
    print("\n===== SECURE GRANT PORTAL =====")        # Print the menu title.
    print("1. Researcher")                               # Researcher submits/views grants.
    print("2. Reviewer")                                 # Reviewer searches, checks, decrypts descriptions.
    print("3. Finance Officer")                          # Finance Officer sums selected encrypted amounts.
    print("4. Exit")                                     # Option to stop program.
    role = input("Choose role: ").strip()                 # Read the user's main menu choice.

    if role == "1":                                      # Enter Researcher role only if 1 is selected.
        while True:                                      # Keep showing Researcher menu until Back.
            print("\n--- RESEARCHER ---")               # Show current role.
            print("1. Submit Grant")                     # Option to create a new grant.
            print("2. View All Grants")                  # Option to display stored encrypted grants.
            print("3. Back")                             # Return to main menu.
            cho = input("Choice: ").strip()               # Read Researcher menu option.

            if cho == "1":                               # Researcher selected Submit Grant.
                gid = input("Grant ID: ").strip()         # Read ID and trim extra spaces.
                desc = input("Description: ")            # Read description as plaintext.
                try:                                     # Catch an amount that is not a number.
                    amount = int(input("Amount: "))      # Read nonnegative integer grant amount.
                except ValueError:                       # Input like 'abc' cannot become an integer.
                    print("Enter a whole-number amount")# Tell the user to retry.
                    continue                             # Go back to Researcher menu.
                if not gid or amount < 0:                 # Reject empty IDs and negative expenses.
                    print("Invalid ID or amount")       # Show input error.
                    continue                             # Skip this submission.
                token = search_token(gid, index_key)      # Convert ID to a stable secret search token.
                if any(r["id"] == token for r in records):# Check if this ID is already in saved records.
                    print("Grant already exists")        # Do not store duplicates.
                    continue                             # Return to Researcher menu.
                enc_desc, iv = aes_cbc_encrypt(desc, aes_key)  # Encrypt description using AES-192.
                enc_amount = paillier_encrypt(amount, ppub)    # Encrypt amount using Paillier public key.
                record = {                                # Prepare the grant dictionary before signing.
                    "id": token,                         # Store protected ID lookup token.
                    "desc": enc_desc.hex(),              # Convert encrypted AES bytes to JSON-safe hex.
                    "iv": iv.hex(),                      # Save IV because AES decryption needs it.
                    "amount": str(enc_amount)            # Store big Paillier ciphertext as decimal text.
                }                                         # Finish the unsigned record.
                data = json.dumps(record, sort_keys=True).encode()  # Same exact bytes for hash and signature.
                record["hash"] = md5_hex(data)            # Attach MD5 hash of unsigned record.
                record["signature"] = rsa_sign_md5(data, rsa_priv).hex()  # RSA-sign it and store hex.
                records.append(record)                    # Add this grant to our list in memory.
                save_json(DATA, records)                  # Write updated list to disk for persistence.
                print("Grant submitted!")                # Confirm submission.

            elif cho == "2":                             # Researcher selected View All Grants.
                if not records:                           # Check whether there are any stored grants.
                    print("No grants submitted")          # Empty list means nothing to display.
                for r in records:                         # Go through every stored grant dictionary.
                    print("\nGrant record:")             # Separate this record visually.
                    print("ID token:", r["id"])         # Display indexed ID token, not plaintext ID.
                    print("Encrypted description:", r["desc"])  # Display AES ciphertext hex.
                    print("Encrypted amount:", r["amount"])    # Display Paillier ciphertext.
                    print("MD5:", r["hash"])              # Display stored MD5 digest.
                    print("RSA signature:", r["signature"])    # Display stored signature hex.

            elif cho == "3":                             # Researcher selected Back.
                break                                     # Leave Researcher inner menu only.
            else:                                         # Choice other than 1, 2 or 3.
                print("Invalid choice")                   # Ask user to choose correctly.

    elif role == "2":                                    # Enter Reviewer role if main choice is 2.
        while True:                                      # Repeat reviewer actions until Back.
            print("\n--- REVIEWER ---")                 # Show Reviewer menu title.
            print("1. Search Grant by ID")               # Find record through blind ID token.
            print("2. Verify MD5")                       # Recalculate hash for tampering check.
            print("3. Verify RSA Signature")             # Check signed authenticity.
            print("4. Decrypt Description + Hex Dump")   # Decrypt description and display hex bytes.
            print("0. Back")                             # Return to main menu.
            ch = input("Choice: ").strip()                # Read Reviewer menu choice.

            if ch in ("1", "2", "3", "4"):                # All four operations first need one grant.
                gid = input("Grant ID: ").strip()         # Ask which grant to inspect.
                token = search_token(gid, index_key)      # Create same token used when grant was saved.
                found = None                              # Assume no matching record initially.
                for r in records:                         # Search encrypted index through saved records.
                    if r["id"] == token:                  # Compare protected token values.
                        found = r                         # Save the matched grant dictionary.
                        break                             # Stop searching once found.
                if found is None:                         # Did the loop fail to locate this ID?
                    print("Grant not found")              # Report missing grant.
                    continue                              # Return to Reviewer menu.

                body = {                                 # Rebuild only original fields, excluding hash/signature.
                    "id": found["id"],                   # Must match exact key name used by Researcher.
                    "desc": found["desc"],               # IMPORTANT: 'desc', not 'description'.
                    "iv": found["iv"],                   # Same IV hex value as submission.
                    "amount": found["amount"]            # Same encrypted amount as submission.
                }                                        # End body to verify.
                data = json.dumps(body, sort_keys=True).encode()  # Serialize exactly like Researcher.
                hash_ok = md5_hex(data) == found["hash"]  # Compare freshly computed MD5 to saved MD5.
                try:                                     # Malformed signature hex can raise an exception.
                    sign_ok = rsa_verify_md5(             # Check RSA signature with public key.
                        data,                             # Bytes of unsigned grant record.
                        bytes.fromhex(found["signature"]),# Saved hex string -> signature bytes.
                        rsa_pub                          # Public key verifies the private-key signature.
                    )                                    # RSA verification returns True/False.
                except (ValueError, TypeError, KeyError): # Treat malformed signature as invalid.
                    sign_ok = False                      # Reject rather than crash.

                if ch == "1":                            # User chose Search Grant.
                    print("Grant found")                 # Matching index token exists.
                    print("Valid:", hash_ok and sign_ok)  # Report whether stored contents are authentic.
                elif ch == "2":                          # User chose MD5 verification.
                    print("MD5 valid" if hash_ok else "MD5 tampered")  # Show hash result.
                elif ch == "3":                          # User chose RSA verification.
                    print("RSA valid" if sign_ok else "RSA invalid")   # Show signature result.
                elif ch == "4":                          # User chose decrypted hex dump.
                    if not (hash_ok and sign_ok):         # Do not decrypt if integrity/authenticity fails.
                        print("Tampering detected")      # Report failure.
                        continue                         # Skip decryption and return to menu.
                    enc_desc = bytes.fromhex(found["desc"]) # Restore AES ciphertext bytes from saved hex.
                    iv = bytes.fromhex(found["iv"])      # Restore original AES IV bytes from saved hex.
                    plain = aes_cbc_decrypt(enc_desc, aes_key, iv) # Decrypt description into plaintext bytes.
                    print("Hex dump:", plain.hex(" "))   # Display plaintext bytes as spaced hex pairs.

            elif ch == "0":                              # Reviewer chose Back (outside the earlier if).
                break                                    # Leave Reviewer inner menu only.
            else:                                        # Any other Reviewer choice.
                print("Invalid choice")                  # Show menu error.

    elif role == "3":                                    # Enter Finance Officer role if main choice is 3.
        while True:                                      # Repeat Finance menu until Back.
            print("\n--- FINANCE OFFICER ---")          # Show current role.
            print("1. Calculate Total Expenditure")      # Sum selected grants homomorphically.
            print("0. Back")                             # Return to main menu.
            ch = input("Choice: ").strip()                # Read Finance option.

            if ch == "1":                                # User requested grant total.
                ids = input("Grant IDs (comma-separated): ").split(",")  # Example: G1,G2,G3.
                ids = [gid.strip() for gid in ids]       # Remove spaces around each typed ID.
                if not all(ids) or len(ids) != len(set(ids)): # Reject empty and duplicate IDs.
                    print("Empty or duplicate Grant IDs")# Prevent invalid/double-counted selections.
                    continue                             # Return to Finance menu.
                encrypted_amounts = []                   # Store selected Paillier ciphertexts only.
                valid = True                             # Assume verification succeeds until proven otherwise.

                for gid in ids:                          # Process each selected Grant ID.
                    token = search_token(gid, index_key)  # Make lookup token from entered ID.
                    found = None                         # No match until searching finds one.
                    for r in records:                    # Search all persisted grant records.
                        if r["id"] == token:              # Does this grant ID token match?
                            found = r                    # Save matching encrypted record.
                            break                        # Stop inner search.
                    if found is None:                    # Grant wasn't in the stored records.
                        print("Grant not found:", gid)   # Tell Finance which ID failed.
                        valid = False                    # Mark selection invalid.
                        break                            # Stop processing all selected IDs.

                    body = {                             # Recreate exact fields the Researcher signed.
                        "id": found["id"],               # Same protected ID.
                        "desc": found["desc"],           # Same AES-encrypted description.
                        "iv": found["iv"],               # Same AES IV.
                        "amount": found["amount"]        # Same Paillier ciphertext.
                    }                                    # Don't include hash/signature themselves.
                    data = json.dumps(body, sort_keys=True).encode()  # Make identical signed bytes.
                    hash_ok = md5_hex(data) == found["hash"]  # Recompute/compare saved MD5.
                    try:                                 # Handle corrupt signature hex gracefully.
                        sign_ok = rsa_verify_md5(        # Verify RSA authenticity.
                            data,                        # Original signed bytes.
                            bytes.fromhex(found["signature"]), # Stored signature hex -> bytes.
                            rsa_pub                     # Verify using RSA public key.
                        )                                # End signature verification.
                    except (ValueError, TypeError, KeyError): # Invalid signature format.
                        sign_ok = False                  # Treat record as unauthentic.
                    if not (hash_ok and sign_ok):         # Reject if either MD5 or RSA fails.
                        print("Verification failed:", gid) # Name rejected grant.
                        valid = False                    # Prevent any final total.
                        break                            # Stop checking further grants.
                    encrypted_amounts.append(int(found["amount"])) # Collect ciphertext; don't decrypt individually.

                if valid and encrypted_amounts:          # Sum only when every selected grant passed verification.
                    enc_total = paillier_add(encrypted_amounts, ppub) # Homomorphic addition without decrypting inputs.
                    total = paillier_decrypt(enc_total, ppub, ppriv)   # Decrypt ONLY the combined ciphertext.
                    print("Encrypted total:", enc_total) # Show combined encrypted result.
                    print("Final expenditure:", total)   # Show plaintext total to Finance Officer.

            elif ch == "0":                              # Finance Officer chose Back.
                break                                    # Leave Finance inner menu.
            else:                                        # Other unknown Finance choice.
                print("Invalid choice")                  # Show error to user.

    elif role == "4":                                    # Main-menu Exit selected.
        print("Exiting portal")                          # Confirm shutdown.
        break                                            # Stop outermost menu loop.
    else:                                                # Unknown main-menu option.
        print("Invalid choice")                          # Show error and repeat main menu.
