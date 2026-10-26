import json                         # Store patient records and keys as JSON.
import hashlib                      # Generate SHA-256 hashes.
import hmac                         # Create searchable diagnosis tokens.
import math                         # Required for Paillier calculations.
import secrets                      # Generate secure random numbers.

from pathlib import Path           # Create, read and write .txt files.

from Crypto.Cipher import AES       # Encrypt and decrypt using AES.
from Crypto.PublicKey import RSA    # Generate RSA public/private keys.
from Crypto.Signature import pkcs1_15  # RSA digital signatures.
from Crypto.Hash import SHA256      # Hash object required by RSA signatures.
from Crypto.Random import get_random_bytes  # Generate AES keys and IVs.
from Crypto.Util.Padding import pad, unpad  # Handle AES block padding.
from Crypto.Util.number import getPrime     # Generate Paillier prime numbers.

# STEP 1: Define the two files
PLAIN = Path("Patient_records.txt")
ENCRYPTED = Path("encrypted_patient_records.txt")

patients = [
    {"Patient_id": "P101", "Patient_name": "Asha", "Diagnosis": "Diabetes", "Blood_glucose": 180, "Treatment": "Insulin"},
    {"Patient_id": "P102", "Patient_name": "Ravi", "Diagnosis": "Fever", "Blood_glucose": 95, "Treatment": "Paracetamol"},
    {"Patient_id": "P103", "Patient_name": "Neha", "Diagnosis": "Diabetes", "Blood_glucose": 160, "Treatment": "Metformin"},
    {"Patient_id": "P104", "Patient_name": "Arjun", "Diagnosis": "Hypertension", "Blood_glucose": 110, "Treatment": "Amlodipine"},
    {"Patient_id": "P105", "Patient_name": "Sara", "Diagnosis": "Anemia", "Blood_glucose": 107, "Treatment": "Iron"}
]


# STEP 3: Write data into the original TXT file
with open(PLAIN, "w", encoding="utf-8") as f:
    for patient in patients:
        f.write(json.dumps(patient) + "\n")  # One patient per line.


def rsa_generate(bits=2048):  # Generate RSA public/private key pair.
    private_key = RSA.generate(bits)  # Create a fresh RSA private key.
    public_key = private_key.publickey()  # Derive public key from private key.
    return public_key, private_key  # Return public key first, private key second.


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

def sha256_hex(data):  # Compute SHA-256 in hexadecimal form.
    if isinstance(data, str):  # Convert text to bytes.
        data = data.encode()  # UTF-8 encode.
    return hashlib.sha256(data).hexdigest()  # Return 64-character SHA-256 hex string.


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


# Generate keys before starting the menu
aes_key = get_random_bytes(32)          # AES-256 key.
rsa_pub, rsa_priv = rsa_generate(2048)  # RSA public/private keys.
ppub, ppriv = paillier_keygen(1024)     # Paillier public/private keys.
index_key = get_random_bytes(32)        # Secret key for diagnosis search.

signature = None  # ADD THIS LINE
while True:

    print("\n===== PATIENT RECORD SYSTEM =====")
    print("1. Display Dataset")
    print("2. Encrypt Dataset using AES")
    print("3. SHA-256 of Patient Record")
    print("4. Sign Dataset using RSA")
    print("5. Verify Signature")
    print("6. Paillier Homomorphic Sum")
    print("7. Search by Diagnosis")
    print("8. Verify and Decrypt Patient")
    print("9. Exit")

    cho = input("Enter choice: ")

    if cho == "1":

        with open(PLAIN, "r", encoding="utf-8") as f:  # Read original TXT file.
            for line in f:                            # Read one patient at a time.
                patient = json.loads(line)             # Convert JSON text to dictionary.
                print(patient)                         # Display patient details.

    elif cho == "9":
        break
    elif cho == "2":
        encrypted_records = []                         # Hold encrypted patient records.
        with open(PLAIN, "r", encoding="utf-8") as f:   # Read original TXT dataset.
            for line in f:
                patient = json.loads(line)              # Convert line to patient dictionary.
                data = json.dumps(patient).encode()     # Convert patient record into bytes.
                ct, iv = aes_cbc_encrypt(               # Encrypt record using AES-256-CBC.
                    data, aes_key
                )
                record = {
                    "id_token": search_token(            # Searchable Patient ID.
                        "id:" + patient["Patient_id"], index_key
                    ),
                    "diagnosis_token": search_token(     # Searchable diagnosis.
                        "diagnosis:" + patient["Diagnosis"], index_key
                    ),
                    "ciphertext": ct.hex(),              # Convert encrypted bytes to hex.
                    "iv": iv.hex()                       # Save IV needed for decryption.
                }
                encrypted_records.append(record)         # Add encrypted record to list.
        with open(ENCRYPTED, "w", encoding="utf-8") as f: # Create encrypted TXT file.
            for record in encrypted_records:
                f.write(json.dumps(record) + "\n")      # Save one encrypted record per line.
        signature = None                                # Old signature is no longer valid.
        print("Dataset encrypted and saved successfully!")
    elif cho == "3":
        patient_id = input("Enter Patient ID: ").strip()  # Get ID from user.
        found = False                                     # Track whether patient exists.
        with open(PLAIN, "r", encoding="utf-8") as f:      # Read original patient TXT file.
            for line in f:                                # Read one record at a time.
                patient = json.loads(line)                 # Convert JSON line to dictionary.
                if patient["Patient_id"] == patient_id:    # Match requested Patient ID.
                    record_hash = sha256_hex(json.dumps(patient)) # sha256_hex() accepts a string or bytes. json.dumps(patient)       # Dictionary → String
                    print("Patient ID:", patient_id)
                    print("SHA-256:", record_hash)
                    found = True
                    break
        if not found:
            print("Patient ID not found")
    elif cho == "4":
        data = ENCRYPTED.read_bytes()   # Read complete encrypted TXT file.
        signature = rsa_sign_sha256(data, rsa_priv)     # Sign file using RSA private key.
        print("Dataset signed successfully!")
        print("RSA Signature:", signature.hex())
    elif cho == "5":

        if signature is None or not ENCRYPTED.exists():
            print("Please encrypt and sign the dataset first!")
            continue

        data = ENCRYPTED.read_bytes()

        valid = rsa_verify_sha256(data, signature, rsa_pub)
        print("Original signature valid:", valid)

        tampered = bytearray(data)
        tampered[0] ^= 1

        tampered_valid = rsa_verify_sha256(
            bytes(tampered), signature, rsa_pub
        )

        print("Tampered signature valid:", tampered_valid)
    elif cho == "6":
        encrypted_values = []  
        actual_total = 0 
        with open(PLAIN, "r", encoding="utf-8") as f:
            for line in f:
                patient = json.loads(line)            # Read patient dictionary.
                glucose = int(patient["Blood_glucose"])
                enc = paillier_encrypt(glucose, ppub)  # Encrypt glucose with Paillier.
                encrypted_values.append(enc)          # Store encrypted value.
                actual_total += glucose               # Plaintext comparison only.
        encrypted_sum = paillier_add(
        encrypted_values, ppub
        )    
        final_sum = paillier_decrypt(
        encrypted_sum, ppub, ppriv
        )      
        print("Homomorphic encrypted sum:", encrypted_sum)
        print("Decrypted glucose total:", final_sum)
        print("Actual glucose total:", actual_total)
        print("Verified:", final_sum == actual_total)
    elif cho == "7":
        diagnosis = input("Enter Diagnosis: ")  # User enters disease.
        token = search_token(
            "diagnosis:" + diagnosis, index_key
        )  
        found = False
        with open(ENCRYPTED, "r", encoding="utf-8") as f:
            for line in f:
                record = json.loads(line)       # Read encrypted record.
                if record["diagnosis_token"] == token:
                    ct = bytes.fromhex(record["ciphertext"])
                    iv = bytes.fromhex(record["iv"])
                    data = aes_cbc_decrypt(ct, aes_key, iv)  # Decrypt matched patient.
                    patient = json.loads(data)              # Convert bytes to dictionary
                    print("Patient ID:", patient["Patient_id"])
                    print("Patient Name:", patient["Patient_name"])
                    print("Diagnosis:", patient["Diagnosis"])
                    found = True
            if not found:
                print("No patients found")
    elif cho == "8":
        pid = input("Enter Patient ID: ")
        data = ENCRYPTED.read_bytes()  # Read encrypted TXT file.
        if not rsa_verify_sha256(data, signature, rsa_pub):
            print("Signature verification FAILED! Access denied.")
            continue
        print("Signature VERIFIED!")
        token = search_token("id:" + pid, index_key)  # Create ID search token.
        found = False
        with open(ENCRYPTED, "r", encoding="utf-8") as f:
           for line in f:
               record = json.loads(line)  # Read encrypted record.
               if record["id_token"] == token:
                   ct = bytes.fromhex(record["ciphertext"])  # Restore ciphertext bytes.
                   iv = bytes.fromhex(record["iv"])          # Restore AES IV.
                   decrypted = aes_cbc_decrypt(ct, aes_key, iv)  # Decrypt patient.
                   patient = json.loads(decrypted)              # Convert to dictionary.
                   print("Patient Details:", patient)
                   found = True
                   break
        if not found:
            print("Patient ID not found")

    elif cho == "9":
        break   
