import math  # Gives gcd() and other basic math functions.
import time  # Used to measure encryption/decryption or hashing time.
import random  # Used to generate random values.
import string  # Gives letters/digits.
import hashlib  # Gives SHA-256 hashing.

from Crypto.Cipher import AES  # AES encryption.
from Crypto.PublicKey import RSA  # RSA key generation.
from Crypto.Signature import pkcs1_15  # RSA digital signature.
from Crypto.Hash import SHA256  # SHA-256 for RSA signature.
from Crypto.Random import get_random_bytes  # Random AES key and IV.
from Crypto.Util.Padding import pad, unpad  # AES padding.


def aes_cbc_encrypt(plaintext, key, iv=None):  # AES CBC encryption.

    if isinstance(plaintext, str):  # Convert string to bytes.

        plaintext = plaintext.encode()

    if iv is None:  # Generate IV if not given.

        iv = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_CBC, iv)  # Create AES cipher.

    ciphertext = cipher.encrypt(
        pad(plaintext, AES.block_size)
    )  # Encrypt padded plaintext.

    return ciphertext, iv


def aes_cbc_decrypt(ciphertext, key, iv):  # AES CBC decryption.

    cipher = AES.new(key, AES.MODE_CBC, iv)

    plaintext = unpad(
        cipher.decrypt(ciphertext),
        AES.block_size
    )

    return plaintext


def rsa_generate(bits=2048):  # Generate RSA keys.

    private_key = RSA.generate(bits)

    public_key = private_key.publickey()

    return public_key, private_key


def sha256_hex(data):  # SHA-256 hash.

    if isinstance(data, str):

        data = data.encode()

    return hashlib.sha256(data).hexdigest()


def rsa_sign_sha256(data, private_key):  # Sign data using RSA private key.

    if isinstance(data, str):

        data = data.encode()

    digest = SHA256.new(data)  # Hash the data.

    signature = pkcs1_15.new(private_key).sign(digest)  # Sign hash.

    return signature


def rsa_verify_sha256(data, signature, public_key):  # Verify RSA signature.

    if isinstance(data, str):

        data = data.encode()

    digest = SHA256.new(data)

    try:

        pkcs1_15.new(public_key).verify(
            digest,
            signature
        )

        return True

    except (ValueError, TypeError):

        return False


# ------------------------------------
# DOCTOR SIDE
# ------------------------------------


# Create report file.

with open("report.txt", "w") as file:

    file.write(
        "Patient: Manya\nDiagnosis: Fever\nPrescription: Rest"
    )


# Read report file.

with open("report.txt", "rb") as file:

    data = file.read()


# Generate AES-128 key.

aes_key = get_random_bytes(16)


# AES encrypt report.

encrypted, iv = aes_cbc_encrypt(
    data,
    aes_key
)


# Compute SHA-256 of encrypted report.

stored_hash = sha256_hex(encrypted)


# Generate Doctor RSA keys.

doctor_public, doctor_private = rsa_generate(2048)


# Doctor signs encrypted report using private key.

signature = rsa_sign_sha256(
    encrypted,
    doctor_private
)


# Store everything.

record = {

    "encrypted": encrypted,

    "hash": stored_hash,

    "signature": signature,

    "iv": iv

}


print("Original hash:", record["hash"])


# ------------------------------------
# TAMPERING
# ------------------------------------


# Convert encrypted bytes into editable bytearray.

tampered = bytearray(
    record["encrypted"]
)


# Change one bit of encrypted data.

tampered[0] ^= 1


# Convert back to bytes.

tampered = bytes(tampered)


# ------------------------------------
# VERIFY TAMPERED DATA
# ------------------------------------


# Recompute SHA-256 on tampered encrypted data.

new_hash = sha256_hex(tampered)


# Compare new hash with original stored hash.

integrity = new_hash == record["hash"]


# Verify OLD signature using tampered data.

signature_valid = rsa_verify_sha256(

    tampered,

    record["signature"],

    doctor_public

)


print("Integrity:", integrity)

print("Signature Valid:", signature_valid)


# Both must be valid.

if integrity and signature_valid:

    print("Record is safe")

else:

    print("Tampering detected")
