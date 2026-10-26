import json
import math
import hashlib
import secrets
import hmac
import random
from pathlib import Path
from datetime import datetime, timezone
from Crypto.Hash import SHA256           # SHA-256 hash object used to sign and verify trusted timestamps.
from Crypto.Signature import pkcs1_15    # RSA digital signature algorithm used by the timestamp authority.
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime

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


def elgamal_generate(p=7919, g=2, x=None):  # Generate simple ElGamal keys using a prime p and generator g.
    if x is None:  # Generate private key when one is not supplied.
        x = random.randint(2, p - 2)  # Choose private key in valid range.
    y = pow(g, x, p)  # Compute public component y=g^x mod p.
    return (p, g, y), x  # Return public key tuple and private key x.



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

def search_token(value, index_key):  # Make an exact-match blind index for a field/word.
    if not isinstance(index_key, bytes) or len(index_key) < 16:  # Require a secret index key.
        raise ValueError("Index key must contain at least 16 bytes.")  # Reject weak key input.
    normalized = " ".join(str(value).casefold().split())  # Normalize case and whitespace consistently.
    return hmac.new(index_key, normalized.encode(), hashlib.sha256).hexdigest()  # Return stable keyed token.


def load_json(path, default=None):  # Load earlier records after a restart.
    if not Path(path).exists():  # First run has no database file yet.
        return default  # Return a fresh value.
    return json.loads(Path(path).read_text(encoding="utf-8"))  # Parse saved JSON.


def save_json(path, value):  # Persist keys or records after each change.
    target = Path(path)  # Resolve the destination file.
    temporary = target.with_suffix(target.suffix + ".tmp")  # Write a temporary copy first.
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")  # Serialize the new state.
    temporary.replace(target)  # Replace the old file only after writing completes.

def trusted_timestamp():                              # Generate a timestamp authenticated by our simulated authority.

    ts = datetime.now(timezone.utc).isoformat()       # Get the current UTC time as a string.

    digest = SHA256.new(ts.encode())                   # Hash the timestamp bytes using SHA-256.

    signature = pkcs1_15.new(tsa_priv).sign(digest)    # Sign the timestamp hash using the authority's RSA private key.

    return ts, signature.hex()                         # Return the timestamp and JSON-safe hexadecimal signature.
# Files to store votes and cryptographic keys
DATA = Path("voting_records.json")
KEYS = Path("voting_keys.json")
# Election voting window (UTC, sample dates for the exam)

START = datetime(2026, 10, 26, 0, 0, tzinfo=timezone.utc)
END = datetime(2026, 10, 28, 23, 59, tzinfo=timezone.utc)
# Generate keys only on first run
if not KEYS.exists():
    rsa_pub, rsa_priv = rsa_generate(4096)
    ppub, ppriv = paillier_keygen(1024)
    index_key = get_random_bytes(32)
    # Trusted timestamp authority RSA keys (lab simulation)
    tsa_pub, tsa_priv = rsa_generate(2048)
    save_json(KEYS, {
        "rsa": rsa_priv.export_key().decode(),
        "ppub": ppub,
        "ppriv": ppriv,
        "index": index_key.hex(),
        "tsa": tsa_priv.export_key().decode()
    })
keys = load_json(KEYS)
rsa_priv = RSA.import_key(keys["rsa"])
rsa_pub = rsa_priv.publickey()

# Restore Paillier keys
ppub = keys["ppub"]
ppriv = keys["ppriv"]

# Restore searchable index secret
index_key = bytes.fromhex(keys["index"])

# Restore timestamp authority signing keys
tsa_priv = RSA.import_key(keys["tsa"])
tsa_pub = tsa_priv.publickey()

# Load previously submitted ballots
records = load_json(DATA, [])
CANDIDATES = [1, 2, 3]  # Assume there are 3 candidates in this election.
# The AES key is encrypted with the Election Commission's RSA-4096 public key.
# Here, we use a new AES-256 key for each ballot.
'''
Voter 1
AES Key A → Encrypt ballot 1 → RSA-encrypt Key A
Voter 2
AES Key B → Encrypt ballot 2 → RSA-encrypt Key B
'''
while True:
    print("\n===== SECURE E-VOTING SYSTEM =====")         # Display the application heading.
    print("1. Voter")                                    # Voter can cast a ballot.
    print("2. Election Server")                          # Server will verify and search ballots.
    print("3. Election Commission")                      # Commission will perform encrypted tallying.
    print("0. Exit")                                     # Stop the application.
    inp = input("choice: ")
    if inp == "1":
        password = input("Voter password: ")  # Ask for voter password.

        if password != "123":                # Check voter access.
            print("Access denied")
            continue
        while True:
            print("\n--- VOTER ---")                       # Display Voter menu heading.
            print("1. Cast Vote")                         # Option to submit a new ballot.
            print("2. View Encrypted Submissions")        # Option to display saved encrypted records (lab demo).
            print("0. Back")                              # Return to the main menu.
            cho = input("Choice: ")
            if cho == "1":   
                voter_id = input("voter id:")
                candidate = int(input("candidate id: "))
                constituency = input("concistruncy: ")

                voter_token = search_token(               # Generate a protected, searchable voter identifier.
                    "voter:" + voter_id, index_key         # Prefix separates voter searches from other indexed fields.
                )                       
                ballot = {                                # Create the ballot dictionary.
                    "candidate": candidate,               # Store the selected numerical candidate ID.
                    "constituency": constituency           # Store the voter's constituency ID.
                }                                         # End ballot dictionary.      
                ballot_bytes = json.dumps(ballot, sort_keys=True).encode()  # Convert ballot into reproducible bytes.     
                ballot_file = Path("ballot_12.json")  # Choose a local ballot filename.
                ballot_file.write_bytes(ballot_bytes)     # Save original ballot bytes to the file.       
                digest = hashlib.sha512(ballot_bytes).digest()  # Compute SHA-512 digest as raw bytes.
                ballot_hash = digest.hex()                # Convert digest to hex for JSON storage and display.
                aes_key = get_random_bytes(32)            # Generate a new 32-byte (256-bit) AES key for this ballot.
                encrypted_ballot, iv = aes_cbc_encrypt(   # Encrypt ballot and receive the CBC initialization vector.
                    ballot_bytes, aes_key                 # Use original ballot bytes and the newly generated key.
                )                                         # Receive AES ciphertext and IV.
                # STEP 4: RSA-4096 ENCRYPTION OF AES SESSION KEY

                encrypted_key = rsa_encrypt_bytes(       # Protect the AES session key using RSA-OAEP.
                    aes_key, rsa_pub                      # Use Election Commission's RSA public key.
                )                                         # Get RSA-encrypted AES key as bytes.
                elg_pub, elg_priv = elgamal_generate()    # Generate voter's ElGamal public/private signing keys.
                p, g, y = elg_pub                         # Unpack public modulus, generator and public value.
                signature = elgamal_sign_digest(          # Digitally sign the SHA-512 digest.
                    digest, p, g, elg_priv                # Use ballot digest, ElGamal parameters and private key.
                )    
                encrypted_vote = paillier_encrypt(        # Encrypt candidate ID without exposing its numerical value.
                    candidate, ppub                       # Use the selected candidate and Paillier public key.
                )                                         # Receive encrypted candidate value.
                encrypted_counts = {}                              # Store encrypted vote for each candidate.

                for c in CANDIDATES:                               # Go through Candidate 1, 2, 3.
                
                    value = 1 if candidate == c else 0             # 1 if selected, otherwise 0.

                    encrypted_counts[str(c)] = str(
                        paillier_encrypt(value, ppub)               # Encrypt 0 or 1 using Paillier.
                    )
                ts, ts_signature = trusted_timestamp()    # Obtain UTC timestamp and authority's RSA signature.
                constituency_token = search_token(        # Generate searchable token without storing raw constituency ID.
                    "constituency:" + constituency,       # Prefix distinguishes constituency from voter tokens.
                    index_key                             # Use the same secret index key for future searches.
                )                                         # Get deterministic protected constituency token.
                record = {                                # Create one dictionary containing submission data.
                    "voter_token": voter_token,            # Store protected voter ID for duplicate detection.
                    "constituency_token": constituency_token,  # Store protected constituency for searching.
                    "encrypted_ballot": encrypted_ballot.hex(),  # AES ciphertext bytes converted into hex.
                    "iv": iv.hex(),                        # CBC initialization vector required for decryption.
                    "encrypted_key": encrypted_key.hex(), # RSA-encrypted AES key converted into hex.
                    "hash": ballot_hash,                  # Original SHA-512 digest of ballot bytes.
                    "signature": list(signature),         # ElGamal signature (r,s) stored as a JSON-compatible list.
                    "elgamal_public": list(elg_pub),       # Public ElGamal parameters needed for verification.
                    "encrypted_vote": str(encrypted_vote),# Store large Paillier ciphertext as decimal text.
                    "encrypted_counts": encrypted_counts,  # Store encrypted 0/1 votes for all candidates.
                    "timestamp": ts,                      # Record timestamp issued by the simulated authority.
                    "timestamp_signature": ts_signature   # Store authority's signature for time verification.
                }                                         # Finish submission dictionary.
                records.append(record)                    # Add this ballot to the in-memory records list.
                save_json(DATA, records)                  # Save the updated records into voting_records.json.

                # STEP 11: DISPLAY REQUIRED OUTPUTS
                print("Vote submitted successfully!")    # Confirm that ballot was saved.
                print("SHA-512:", ballot_hash)             # Show ballot's SHA-512 fingerprint.
                print("AES encrypted ballot:", encrypted_ballot.hex())  # Display AES ciphertext in hex.
                print("RSA encrypted AES key:", encrypted_key.hex())    # Display RSA-wrapped session key.
                print("ElGamal signature:", signature)     # Display ElGamal signature pair.
                print("Paillier encrypted vote:", encrypted_vote)       # Display encrypted candidate ID.
                print("Trusted timestamp:", ts)           # Display UTC submission timestamp.
            elif cho == "2":                               # Voter selected View Encrypted Submissions.
            

                if not records:                            # Check if there are no stored ballots.
                    print("No submissions available")      # Display empty-storage message.

                for r in records:                          # Visit each encrypted ballot record.
                    print(r)
            elif cho == "0":                               # Voter wants to return to main menu.
                break                                      # Exit only the Voter inner loop.

            else:                                          # Handle unsupported Voter menu choices.
                print("Invalid choice")                    # Inform user and repeat Voter menu.
    elif inp == "2":                                        # User selected Election Server.
        password = input("Server password: ")  # Ask for server password.
        if password != "456":                 # Check server access.
            print("Access denied")
            continue

    # Your existing Server while True loop stays below.
        while True:                                         # Repeat Server menu until Back.
            print("\n--- ELECTION SERVER ---")             # Display Server heading.
            print("1. Verify Ballot")                       # Verify ballot hash, signature, and timestamp.
            print("2. Search by Constituency")             # Will implement next.
            print("3. Search by Time Range")                # Will implement next.
            print("0. Back")                                # Return to main menu.
            cho = input("Choice: ")
            if cho == "1":  
                voter_id = input("Voter ID: ")
                token = search_token(                       # Recreate the voter's searchable token.
                    "voter:" + voter_id, index_key
                )
                found = None  
                for r in records:                           # Search all stored encrypted ballots.
                    if r["voter_token"] == token:            # Compare voter search tokens.
                        found = r                            # Save the matching record.
                        break                                # Stop searching.
                if found is None:                           # Check if no ballot was found.
                    print("Ballot not found")                # Inform server of missing record.
                    continue                                # Return to Server menu.
                encrypted_key = bytes.fromhex(found["encrypted_key"])  # Restore RSA ciphertext bytes.
                aes_key = rsa_decrypt_bytes(             # Recover the original AES session key.
                        encrypted_key, rsa_priv              # Use Commission's RSA private key.
                    )
                encrypted_ballot = bytes.fromhex(found["encrypted_ballot"])  # Restore AES ciphertext bytes.
                iv = bytes.fromhex(found["iv"])          # Restore AES-CBC IV.
                ballot_bytes = aes_cbc_decrypt(          # Decrypt ballot using recovered session key.
                        encrypted_ballot, aes_key, iv
                    )
                digest = hashlib.sha512(ballot_bytes).digest()  # Recompute SHA-512 of received ballot.

                hash_ok = digest.hex() == found["hash"]  # Compare with original stored hash.
                p, g, y = found["elgamal_public"]        # Read voter's ElGamal public parameters.
                sign_ok = elgamal_verify_digest(        # Verify voter's digital signature.
                    digest, found["signature"], p, g, y
                )
                ts_digest = SHA256.new(                  # Recalculate hash of trusted timestamp.
                    found["timestamp"].encode()
                )
                pkcs1_15.new(tsa_pub).verify(            # Verify timestamp authority's RSA signature.
                    ts_digest,
                    bytes.fromhex(found["timestamp_signature"])
                )
                timestamp_ok = True                     # TSA signature verification succeeded.
                submitted = datetime.fromisoformat(     # Convert stored timestamp string to datetime.
                    found["timestamp"]
                )

                deadline_ok = START <= submitted <= END  # Check election opening and closing times.
                ballot = json.loads(ballot_bytes)       # Parse decrypted ballot for consistency checks.
                constituency_ok = search_token(          # Recalculate constituency search token.
                    "constituency:" + ballot["constituency"],
                    index_key
                ) == found["constituency_token"]         # Compare it with saved index token.
                print("SHA-512 valid:", hash_ok)         # Display integrity verification result.
                print("ElGamal signature valid:", sign_ok)  # Display signature result.
                print("Trusted timestamp valid:", timestamp_ok)  # Display TSA result.
                print("Within deadline:", deadline_ok)  # Display deadline verification.
                print("Constituency index valid:", constituency_ok)  # Display index consistency.
                if hash_ok and sign_ok and timestamp_ok and deadline_ok and constituency_ok:
                    print("BALLOT VERIFIED")             # Accept when these checks pass.
                else:
                    print("BALLOT REJECTED")             # Reject if any check fails.     # Report corrupted or unverifiable record.
            elif cho == "2":                                # Constituency search option.
                print("We will implement constituency search next")
            elif cho == "3":                                # Time-range search option.
                print("We will implement time-range search next")
            elif cho == "0":                                # Server selected Back.
                break                                      # Leave Server menu.
                
        else:                                          # Invalid Server option.
            print("Invalid choice")                    # Display input error    
    elif inp == "3":                              # Election Commission.
        password = input("Commission password: ")  # Ask for commission password.
    
        if password != "789":                     # Check commission access.
            print("Access denied")
            continue

    # Your existing Commission code stays below.

        print("\n--- FINAL VOTE COUNT ---")

        for c in CANDIDATES:                      # Count one candidate at a time.

            votes = []                            # Store encrypted votes for candidate c.

            for r in records:                     # Go through all voter records.

                votes.append(
                    int(r["encrypted_counts"][str(c)])
                )                                 # Collect encrypted 0 or 1.

            if not votes:                         # No votes submitted.
                print("No votes available")
                continue

            enc_total = paillier_add(votes, ppub)  # Add encrypted votes.

            final = paillier_decrypt(
                enc_total, ppub, ppriv
            )                                     # Decrypt only the final sum.

            print("Candidate", c, "votes:", final) # Display candidate's vote count.
