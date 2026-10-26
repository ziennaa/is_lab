'''
HR 
submits 
employee records
auditors
verify their authenticity and integrity

finance department calculates the
 total bonus expenditure without decrypting individual bonuses.


 HR
-Enter Employee ID, Employee Name, Department, and Bonus Amount.
Encrypt Employee Name and Department using AES-256-CBC.
Encrypt Bonus Amount using Paillier.
Compute a SHA-256 hash of the encrypted record.
Sign the record using an RSA digital signature with SHA-256.
- Store records persistently and allow HR to view previous submissions.

2. Auditor
- Search an employee using a searchable index on Employee ID.
- Recompute SHA-256 to detect tampering.
- Verify the RSA signature.
- If verification succeeds, decrypt Employee Name and Department and display them.


3. Finance Department
- Select multiple Employee IDs.
- Verify the integrity and signature of each selected record.
- Homomorphically add the encrypted bonus amounts.
- Decrypt only the final total bonus.
- Reject invalid records and duplicate Employee IDs.

4. Additional requirement
- Demonstrate tampering by modifying one stored encrypted department field.
- Show that the Auditor detects the modification.
- Maintain persistent JSON storage so records can be loaded after a program restart.
'''
import json
import math
import hashlib
import secrets
import hmac
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import MD5, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime
key256 = get_random_bytes(32) 

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




def paillier_decrypt(ciphertext, public, private):  # Decrypt one ciphertext, preferably only the aggregate.
    n = int(public["n"])  # Read modulus.
    c = int(ciphertext)  # Convert serialized ciphertext.
    if not 0 < c < n * n or math.gcd(c, n * n) != 1:  # Check ciphertext group membership.
        raise ValueError("Invalid Paillier ciphertext.")  # Handle altered storage cleanly.
    l_value = (pow(c, int(private["lambda"]), n * n) - 1) // n  # Evaluate L(c^lambda).
    return l_value * int(private["mu"]) % n  # Recover the sum modulo n.

def sha256_hex(data):  # Compute SHA-256 in hexadecimal form.
    if isinstance(data, str):  # Convert text to bytes.
        data = data.encode()  # UTF-8 encode.
    return hashlib.sha256(data).hexdigest()  # Return 64-character SHA-256 hex string.

def rsa_generate(bits=2048):  # Generate RSA public/private key pair.
    private_key = RSA.generate(bits)  # Create a fresh RSA private key.
    public_key = private_key.publickey()  # Derive public key from private key.
    return public_key, private_key  # Return public key first, private key second.


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
    
def search_token(value, index_key):  # Make an exact-match blind index for a field/word.
    if not isinstance(index_key, bytes) or len(index_key) < 16:  # Require a secret index key.
        raise ValueError("Index key must contain at least 16 bytes.")  # Reject weak key input.
    normalized = " ".join(str(value).casefold().split())  # Normalize case and whitespace consistently.
    return hmac.new(index_key, normalized.encode(), hashlib.sha256).hexdigest()  # Return stable keyed token.

def load_json(path, default=None):
    if not Path(path).exists():
        return default
    return json.loads(Path(path).read_text(encoding="utf-8"))

def save_json(path, value):
    target = Path(path)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    temporary.replace(target)
def to_string(data):
    if isinstance(data, str):
        return data
    elif isinstance(data, tuple):
        return json.dumps(list(data))
    else:
        return json.dumps(data)


DATA = Path("employee_data.json")  # File containing previously submitted encrypted grants.
KEYS = Path("ekeys.json")      # File holding keys so old grants can still be opened after restart.

if not KEYS.exists():                                     # Only generate keys if this is the first run.
    rsa_pub, rsa_priv = rsa_generate(2048)               # Make a matching RSA key pair for signatures.
    aes_key = get_random_bytes(32)                       # 24 bytes = AES-192 key.
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


while True:                                              # Show the main menu until the user exits.
    print("\n===== EMPLOYEE PORTAL =====")        # Print the menu title.
    print("1. HR OFFICE")                               # Researcher submits/views grants.
    print("2. Auditor")                                 # Reviewer searches, checks, decrypts descriptions.
    print("3. Finance Dept")                          # Finance Officer sums selected encrypted amounts.
    print("4. Exit")                                     # Option to stop program.
    ch = input("Choose role: ")              # Read the user's main menu choice.
    if ch == "1":                                      # Enter Researcher role only if 1 is selected.
            while True:                                      # Keep showing Researcher menu until Back.
                print("\n--- HR Officer ---")               # Show current role.
                print("1. employee details enter: ")                     # Option to create a new grant.
                print("2. View All records")                  # Option to display stored encrypted grants.
                print("3. Back")                             # Return to main menu.
                cho = input("Choice: ")           # Read Researcher menu option.
                if cho == "1":
                    id = input("enter employee id: ")
                    name = input("enter employee name: ")
                    dept = input("enter dept: ")
                    bonusamount = int(input("enter amount: "))
                    token = search_token(id, index_key)
                    data = to_string((name, dept))
                    encrypted, iv = aes_cbc_encrypt(data, aes_key)
                    encrypted_bonus = paillier_encrypt(bonusamount, ppub)
                    record = {                                # Prepare the grant dictionary before signing.
                        "id": token,                         # Store protected ID lookup token.
                        "encrypted": encrypted.hex(),              # Convert encrypted AES bytes to JSON-safe hex.
                        "iv": iv.hex(),                      # Save IV because AES decryption needs it.
                        "amount": str(encrypted_bonus)            # Store big Paillier ciphertext as decimal text.
                    }  
                    rec = json.dumps(record, sort_keys=True).encode() 
                    record["hash"] = sha256_hex(rec)
                    record["signature"] = rsa_sign_sha256(rec, rsa_priv).hex()
                    records.append(record)  
                    save_json(DATA, records) 
                    print("employee record submitted!")
                elif cho == "2":
                    for r in records:
                        print(r)
                elif cho == "3":
                    break
                else:
                    print("invalid choice")
    elif ch == "2":
        while True:
            print("auditor")
            print("1 auditor, search, verification, decryption")
            print("2. tampering verification failed ")
            print("3. back")    
            cho = input("enter choice: ")
            if cho == "1":
                id = input("enter id: ")
                token = search_token(id, index_key)
                found = None
                for r in records:                         # Search encrypted index through saved records.
                    if r["id"] == token:                  # Compare protected token values.
                        found = r                         # Save the matched grant dictionary.
                        break                             # Stop searching once found.
                    if found is None:                         # Did the loop fail to locate this ID?
                        print(" not found")              # Report missing grant.
                        continue                              # Return to Reviewer menu.
                body = {                                 # Rebuild only original fields, excluding hash/signature.
                    "id": found["id"],                   # Must match exact key name used by Researcher.
                    "encrypted": found["encrypted"],               # IMPORTANT: 'desc', not 'description'.
                    "iv": found["iv"],                   # Same IV hex value as submission.
                    "amount": found["amount"]            # Same encrypted amount as submission.
                }   
                data = json.dumps(body, sort_keys=True).encode()
                hash_ok = sha256_hex(data) == found["hash"]
                signok = rsa_verify_sha256(data, bytes.fromhex(found["signature"]), rsa_pub) 
                if hash_ok and signok:
                    print("verified, no tampering ")
                    print("decryption")
                    enc = bytes.fromhex(found["encrypted"])
                    iv = bytes.fromhex(found["iv"])
                    plain = aes_cbc_decrypt(enc, aes_key, iv)
                    plain = plain.decode()
                    print(plain)
            elif cho == "2":
                r = records[0]
                tampered = bytearray(bytes.fromhex(r["encrypted"]))  # Make mutable copy of ciphertext.
                tampered[0] ^= 1  # Flip one bit to simulate one-character/byte tampering.
                tampered_hash = sha256_hex(bytes(tampered))  # Hash tampered ciphertext.
                tamper_integrity_ok = tampered_hash == r["hash"]  # This should be False.
                if tamper_integrity_ok is False:
                    print("verification failed, data is tampered")
            elif cho == "3":
                break
            else:
                print("invalid")
    elif ch == "3":
        while True:
            print("finance: ")
            print("1. verification plus tootal bonus amount")
            print("2. back")
            cho = input("enter choice: ")
            if cho == "1":                                # User requested grant total.
                ids = input(" IDs (comma-separated): ").split(",") 
                encrypted_amounts = []
                valid = True
                for gid in ids:
                    gid = gid.strip()
                    token = search_token(gid, index_key)
                    found = None
                    for r in records:
                        if r["id"] == token:
                            found = r
                            break
                    if found is None:
                        print("Grant not found:", gid)
                        valid = False
                        break
                    body = {
                        "id": found["id"],
                        "encrypted": found["encrypted"],
                        "iv": found["iv"],
                        "amount": found["amount"]
                    }

                    data = json.dumps(body, sort_keys=True).encode()

                    hash_ok = sha256_hex(data) == found["hash"]

                    sign_ok = rsa_verify_sha256(
                        data,
                        bytes.fromhex(found["signature"]),
                        rsa_pub
                    )
                    if not hash_ok or not sign_ok:
                        print("Verification failed:", gid)
                        valid = False
                        break

                    # Add encrypted amount to list
                    encrypted_amounts.append(int(found["amount"]))
                if valid and encrypted_amounts:
                    enc_total = paillier_add(encrypted_amounts, ppub)
                    total = paillier_decrypt(enc_total, ppub, ppriv)

                    print("Encrypted Total:", enc_total)
                    print("Final Expenditure:", total)
            elif cho == "2":
                break
    elif ch == "4":
        break 
    else:
        print("invalid")



                
