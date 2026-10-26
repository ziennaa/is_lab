"""EXTRA MIXED IS LAB PATTERNS (LABS 1-8).
Run: python IS_Extra_Mixed_Lab_Combinations.py
Each example is standalone inside this file; no imports from your toolkit.
These are lab demonstrations, not production security implementations.
"""
import json  # Serialize records consistently before hashing and signing.
import hmac  # Create keyed integrity tags and blind search indexes.
import hashlib  # Calculate SHA-256 and derive demonstration keys.
import secrets  # Create cryptographically random integers.
import math  # Calculate greatest common divisors and Paillier key values.
from Crypto.Cipher import AES, PKCS1_OAEP  # Encrypt data using AES and wrap keys using RSA-OAEP.
from Crypto.PublicKey import RSA  # Generate RSA public/private keys.
from Crypto.Signature import pkcs1_15  # Sign and verify SHA-256 digests using RSA.
from Crypto.Hash import SHA256  # Supply a SHA-256 hash object for RSA signatures.
from Crypto.Random import get_random_bytes  # Generate secure AES keys and IVs.
from Crypto.Util.Padding import pad, unpad  # Add and remove AES-CBC padding.
from Crypto.Util.number import getPrime  # Generate primes for Paillier.


def encode_record(record):  # Turn a dictionary into stable bytes for signing and hashing.
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode()  # Use identical serialization when verifying.


def aes_encrypt(data, key):  # Encrypt bytes or text with AES-CBC.
    data = data.encode() if isinstance(data, str) else data  # Convert text into bytes if necessary.
    iv = get_random_bytes(16)  # Generate one fresh AES-CBC IV.
    ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, 16))  # Pad and encrypt input bytes.
    return ciphertext, iv  # Return ciphertext and IV for storage or transmission.


def aes_decrypt(ciphertext, iv, key):  # Decrypt AES-CBC using the original key and IV.
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), 16)  # Decrypt and remove padding.


def rsa_keys():  # Generate an RSA key pair for encryption or signing.
    private = RSA.generate(2048)  # Create a 2048-bit RSA private key.
    return private.publickey(), private  # Return public key first, private key second.


def sign_record(record, private):  # Sign the canonical SHA-256 digest of a dictionary.
    return pkcs1_15.new(private).sign(SHA256.new(encode_record(record)))  # Return an RSA signature.


def verify_record(record, signature, public):  # Verify an RSA signature without decrypting any data.
    try:  # PyCryptodome raises an exception on invalid signatures.
        pkcs1_15.new(public).verify(SHA256.new(encode_record(record)), signature)  # Verify exact same stored fields.
        return True  # Report valid signature.
    except (ValueError, TypeError):  # Invalid data or signature enters this branch.
        return False  # Report tampering or wrong signing key.


def token_for(value, index_key):  # Generate a searchable encrypted index for an exact field value.
    return hmac.new(index_key, str(value).strip().casefold().encode(), hashlib.sha256).hexdigest()  # Store token, not original identifier.


def paillier_keys(bits=1024):  # Create Paillier additive-homomorphic public/private keys.
    p = getPrime(bits // 2)  # Generate a random prime p.
    q = getPrime(bits // 2)  # Generate a random prime q.
    while p == q:  # Ensure the two primes differ.
        q = getPrime(bits // 2)  # Replace the repeated prime.
    n = p * q  # Compute the Paillier modulus.
    lam = math.lcm(p - 1, q - 1)  # Compute the private exponent.
    mu = pow(lam, -1, n)  # Calculate the inverse for g=n+1.
    return (n, n + 1), (lam, mu)  # Return the public and private parameters.


def paillier_encrypt(value, public):  # Encrypt a nonnegative integer smaller than n.
    n, g = public  # Read the Paillier modulus and generator.
    if not 0 <= value < n:  # Check the valid Paillier plaintext range.
        raise ValueError("Amount must be between 0 and n-1")  # Reject invalid inputs.
    r = secrets.randbelow(n - 1) + 1  # Choose random encryption factor.
    while math.gcd(r, n) != 1:  # Check that r has an inverse modulo n.
        r = secrets.randbelow(n - 1) + 1  # Resample r when necessary.
    return pow(g, value, n*n) * pow(r, n, n*n) % (n*n)  # Calculate the Paillier ciphertext.


def paillier_weighted_sum(encrypted_values, weights, public):  # Compute sum(weight * value) on ciphertexts.
    n, _ = public  # Read the Paillier modulus.
    total = 1  # Start with the neutral ciphertext-group element.
    for ciphertext, weight in zip(encrypted_values, weights):  # Process each encrypted amount and public weight.
        total = total * pow(ciphertext, weight, n*n) % (n*n)  # Raising ciphertext to weight multiplies its plaintext.
    return total  # Return the encrypted weighted sum, without individual decryptions.


def paillier_decrypt(ciphertext, public, private):  # Decrypt an aggregate ciphertext.
    n, _ = public  # Read the modulus.
    lam, mu = private  # Read private parameters.
    return ((pow(ciphertext, lam, n*n) - 1) // n) * mu % n  # Recover plaintext modulo n.


def elgamal_keys(p=7919, g=2):  # Create textbook ElGamal signature keys for a lab demo.
    x = secrets.randbelow(p - 3) + 2  # Choose a random private key.
    y = pow(g, x, p)  # Derive the corresponding public key.
    return (p, g, y), x  # Return public parameters and private integer.


def elgamal_sign(data, public, private):  # Create a textbook ElGamal signature on SHA-256(data).
    p, g, _ = public  # Read public parameters.
    h = int.from_bytes(hashlib.sha256(data).digest(), "big") % (p - 1)  # Convert hash to modular integer.
    k = secrets.randbelow(p - 3) + 2  # Draw a signing nonce.
    while math.gcd(k, p - 1) != 1:  # Require an invertible nonce.
        k = secrets.randbelow(p - 3) + 2  # Draw another nonce if necessary.
    r = pow(g, k, p)  # Compute the first signature value.
    s = ((h - private*r) * pow(k, -1, p - 1)) % (p - 1)  # Compute the second signature value.
    return r, s  # Return the ElGamal signature pair.


def elgamal_verify(data, signature, public):  # Verify textbook ElGamal against the supplied data.
    p, g, y = public  # Read public parameters.
    r, s = signature  # Read both signature values.
    if not (1 <= r < p and 0 <= s < p - 1):  # Reject invalid signature range.
        return False  # Report invalid signature format.
    h = int.from_bytes(hashlib.sha256(data).digest(), "big") % (p - 1)  # Recompute the message digest.
    return pow(g, h, p) == pow(y, r, p) * pow(r, s, p) % p  # Compare the ElGamal verification equation.


def demo_dh_aes_hmac():  # MIX A: Lab 3 DH + Lab 2 AES + Lab 5 keyed integrity.
    p, g = 7919, 2  # Use small DH parameters for classroom demonstration only.
    alice_secret = secrets.randbelow(p - 3) + 2  # Alice chooses a private DH value.
    bob_secret = secrets.randbelow(p - 3) + 2  # Bob chooses a private DH value.
    alice_public = pow(g, alice_secret, p)  # Alice calculates the public exchange value.
    bob_public = pow(g, bob_secret, p)  # Bob calculates the public exchange value.
    shared_a = pow(bob_public, alice_secret, p)  # Alice computes the common secret.
    shared_b = pow(alice_public, bob_secret, p)  # Bob computes the same secret.
    key = hashlib.sha256(str(shared_a).encode()).digest()  # Derive AES-256 key for this simple lab exercise.
    mac_key = hashlib.sha256(b"mac:" + str(shared_a).encode()).digest()  # Derive a separate HMAC key.
    message = input("Enter private message: ")  # Accept the message to transmit.
    ciphertext, iv = aes_encrypt(message, key)  # Encrypt message with shared AES key.
    tag = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).hexdigest()  # Authenticate IV and ciphertext.
    print("DH keys match:", shared_a == shared_b)  # Verify both parties obtained the same DH secret.
    print("Ciphertext:", ciphertext.hex())  # Display encrypted bytes as hexadecimal.
    print("HMAC valid:", hmac.compare_digest(tag, hmac.new(mac_key, iv + ciphertext, hashlib.sha256).hexdigest()))  # Check the received tag.
    print("Recovered:", aes_decrypt(ciphertext, iv, key).decode())  # Decrypt after successful HMAC verification.
    altered = bytearray(ciphertext)  # Make a mutable copy to simulate tampering.
    altered[0] ^= 1  # Flip a ciphertext bit.
    print("Tampered HMAC valid:", hmac.compare_digest(tag, hmac.new(mac_key, iv + bytes(altered), hashlib.sha256).hexdigest()))  # Show modification is detected.


def demo_search_signature_weighted_sum():  # MIX B: Labs 2, 5, 6, 7, 8 together.
    aes_key = get_random_bytes(32)  # Create an AES-256 key to protect a private field.
    index_key = get_random_bytes(32)  # Create a separate secret key for searchable indexes.
    public_rsa, private_rsa = rsa_keys()  # Generate RSA keys for record signatures.
    public_p, private_p = paillier_keys()  # Generate Paillier keys for encrypted totals.
    records = []  # Store submitted records in a list.
    count = int(input("How many records? "))  # Read the number of records.
    for _ in range(count):  # Accept each record independently.
        item_id = input("ID: ")  # Read a searchable identifier.
        description = input("Private description: ")  # Read a confidential text value.
        amount = int(input("Nonnegative amount: "))  # Read a Paillier plaintext amount.
        ciphertext, iv = aes_encrypt(description, aes_key)  # Encrypt the private description.
        record = {"token": token_for(item_id, index_key), "ciphertext": ciphertext.hex(), "iv": iv.hex(), "amount": str(paillier_encrypt(amount, public_p))}  # Store only indexed/encrypted content.
        signature = sign_record(record, private_rsa)  # Sign the exact encrypted record dictionary.
        records.append({"body": record, "signature": signature.hex()})  # Save signed record in memory.
    query = input("Search ID: ")  # Request one original ID for exact-match lookup.
    found = next((r for r in records if r["body"]["token"] == token_for(query, index_key)), None)  # Search with protected token.
    if found is not None:  # Only process an existing match.
        valid = verify_record(found["body"], bytes.fromhex(found["signature"]), public_rsa)  # Verify stored data before decryption.
        print("Signature valid:", valid)  # Report signature status.
        if valid:  # Only decrypt a verified record.
            print("Description:", aes_decrypt(bytes.fromhex(found["body"]["ciphertext"]), bytes.fromhex(found["body"]["iv"]), aes_key).decode())  # Show recovered description.
    else:  # Handle an unknown index value.
        print("Record not found")  # Report no match.
    if not records:  # Skip addition when there are no submitted records.
        return  # Finish the demo.
    weights = [int(input("Public weight for record " + str(i+1) + ": ")) for i in range(len(records))]  # Read public nonnegative weights.
    if any(weight < 0 for weight in weights):  # Check whether each weight is valid for this demo.
        print("Weights must be nonnegative")  # Explain the constraint.
        return  # Skip invalid aggregation.
    if not all(verify_record(r["body"], bytes.fromhex(r["signature"]), public_rsa) for r in records):  # Verify every record before aggregation.
        print("Tampering detected; aggregation blocked")  # Reject unauthentic records.
        return  # Avoid totaling invalid records.
    enc_values = [int(r["body"]["amount"]) for r in records]  # Collect Paillier ciphertexts without decrypting.
    enc_total = paillier_weighted_sum(enc_values, weights, public_p)  # Compute encrypted sum of weighted amounts.
    print("Encrypted weighted total:", enc_total)  # Show aggregated ciphertext.
    print("Final decrypted weighted total (mod n):", paillier_decrypt(enc_total, public_p, private_p))  # Decrypt only the final aggregate.


def demo_elgamal_aes_tamper():  # MIX C: Lab 2 AES + Lab 5 hashing + Lab 6 ElGamal signatures.
    aes_key = get_random_bytes(24)  # Create an AES-192 key.
    public, private = elgamal_keys()  # Create ElGamal signing keys.
    message = input("Sensitive message: ")  # Accept plaintext input.
    ciphertext, iv = aes_encrypt(message, aes_key)  # Encrypt the message using AES-192-CBC.
    body = {"ciphertext": ciphertext.hex(), "iv": iv.hex()}  # Store consistent encrypted fields.
    serialized = encode_record(body)  # Serialize the exact fields to sign.
    original_hash = hashlib.sha256(serialized).hexdigest()  # Save the SHA-256 integrity digest.
    signature = elgamal_sign(serialized, public, private)  # Sign encrypted fields using ElGamal.
    print("SHA-256 valid:", hashlib.sha256(encode_record(body)).hexdigest() == original_hash)  # Check hash integrity.
    print("ElGamal signature valid:", elgamal_verify(encode_record(body), signature, public))  # Check authenticity.
    print("Recovered:", aes_decrypt(ciphertext, iv, aes_key).decode())  # Decrypt verified ciphertext.
    bad_body = dict(body)  # Copy the signed record before tampering.
    bad = bytearray(ciphertext)  # Create mutable ciphertext.
    bad[0] ^= 1  # Tamper with one encrypted byte.
    bad_body["ciphertext"] = bytes(bad).hex()  # Replace only the encrypted field in the copied record.
    print("Tampered SHA-256 valid:", hashlib.sha256(encode_record(bad_body)).hexdigest() == original_hash)  # Show hash mismatch.
    print("Tampered ElGamal signature valid:", elgamal_verify(encode_record(bad_body), signature, public))  # Show signature rejection.


def demo_rsa_aes_sha():  # MIX D: Lab 2 AES + Lab 3 RSA-OAEP hybrid encryption + Lab 5 SHA-256.
    public, private = rsa_keys()  # Receiver generates an RSA key pair and retains private key.
    message = input("Long confidential message: ")  # Read any length of message.
    aes_key = get_random_bytes(32)  # Sender creates a fresh AES-256 session key.
    ciphertext, iv = aes_encrypt(message, aes_key)  # Sender encrypts data with AES.
    wrapped_key = PKCS1_OAEP.new(public).encrypt(aes_key)  # Sender encrypts only the AES key using receiver RSA public key.
    digest = hashlib.sha256(message.encode()).hexdigest()  # Sender hashes original plaintext for lab verification.
    print("AES ciphertext:", ciphertext.hex())  # Show encrypted message.
    print("RSA-encrypted AES key:", wrapped_key.hex())  # Show encrypted session key.
    restored_key = PKCS1_OAEP.new(private).decrypt(wrapped_key)  # Receiver restores session key using its RSA private key.
    restored_message = aes_decrypt(ciphertext, iv, restored_key)  # Receiver decrypts message using AES.
    print("SHA-256 valid:", hashlib.sha256(restored_message).hexdigest() == digest)  # Compare digests.
    print("Recovered:", restored_message.decode())  # Show decrypted plaintext.


while True:  # Display the menu until the user exits.
    print("\n1. DH + AES + HMAC")  # Offer Diffie-Hellman secure-message demo.
    print("2. Search + AES + RSA sign + weighted Paillier")  # Offer searchable record and encrypted aggregate demo.
    print("3. AES + ElGamal signature + tampering")  # Offer ElGamal verification demo.
    print("4. RSA-OAEP + AES + SHA-256")  # Offer hybrid encryption demo.
    print("0. Exit")  # Offer exit option.
    choice = input("Choose: ").strip()  # Read menu selection.
    if choice == "1":  # User selected DH secure messaging.
        demo_dh_aes_hmac()  # Run demo A.
    elif choice == "2":  # User selected searchable encrypted records.
        demo_search_signature_weighted_sum()  # Run demo B.
    elif choice == "3":  # User selected ElGamal tamper demonstration.
        demo_elgamal_aes_tamper()  # Run demo C.
    elif choice == "4":  # User selected hybrid RSA/AES encryption.
        demo_rsa_aes_sha()  # Run demo D.
    elif choice == "0":  # User selected exit.
        break  # End the program.
    else:  # User entered an unsupported menu option.
        print("Invalid choice")  # Ask for another option.
