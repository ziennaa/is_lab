import math  # Gives gcd() and other basic math functions.
import time  # Used to measure encryption/decryption or hashing time.
import random  # Used to generate random values for ElGamal/DH and datasets.
import string  # Gives letters/digits for random test strings.
import hashlib  # Gives MD5, SHA-1 and SHA-256 hashing.
import socket  # Used for client-server lab questions.
from datetime import datetime  # Used to generate timestamps.
from pathlib import Path  # Makes file handling simple and readable.

from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP  # Modern symmetric ciphers and RSA-OAEP.
from Crypto.PublicKey import RSA  # Generates and loads RSA public/private keys.
from Crypto.Signature import pkcs1_15  # Creates and verifies RSA digital signatures.
from Crypto.Hash import SHA256  # SHA-256 object compatible with RSA signing.
from Crypto.Random import get_random_bytes  # Secure random bytes for keys/IVs/nonces.
from Crypto.Util.Padding import pad, unpad  # Adds/removes block padding for AES/DES.
from Crypto.Util.number import inverse  # Finds modular inverse for ElGamal/Rabin helpers.


def rsa_generate(bits=2048):
    private_key = RSA.generate(bits)
    public_key = private_key.publickey()
    return public_key, private_key


def rsa_encrypt_bytes(data, public_key):
    if isinstance(data, str):
        data = data.encode()

    cipher = PKCS1_OAEP.new(public_key)

    return cipher.encrypt(data)


def rsa_decrypt_bytes(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(private_key)

    return cipher.decrypt(ciphertext)


def rsa_encrypt_long_message(data, public_key):
    if isinstance(data, str):
        data = data.encode()

    key_bytes = public_key.size_in_bytes()

    max_chunk = key_bytes - 2 * SHA256.digest_size - 2

    max_chunk = min(max_chunk, 190)

    chunks = [
        data[i:i + max_chunk]
        for i in range(0, len(data), max_chunk)
    ]

    return [
        rsa_encrypt_bytes(chunk, public_key)
        for chunk in chunks
    ]


def rsa_decrypt_long_message(chunks, private_key):
    return b"".join(
        rsa_decrypt_bytes(chunk, private_key)
        for chunk in chunks
    )


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode()

    return hashlib.sha256(data).hexdigest()


def rsa_sign_sha256(data, private_key):
    if isinstance(data, str):
        data = data.encode()

    digest = SHA256.new(data)

    signature = pkcs1_15.new(private_key).sign(digest)

    return signature


def rsa_verify_sha256(data, signature, public_key):
    if isinstance(data, str):
        data = data.encode()

    digest = SHA256.new(data)

    try:
        pkcs1_15.new(public_key).verify(digest, signature)

        return True

    except (ValueError, TypeError):

        return False


def timestamp_now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


patients = []

records = []

drpublic, drprivate = rsa_generate(2048)


while True:

    print("hospital system")

    print("1. doctor")

    print("2. nurse")

    print("3. admin")

    role = input("enter role: ")


    if role == "1":

        patient = {
            "name": input("Enter name: "),
            "age": input("Enter age: "),
            "gender": input("gender: "),
            "blood group": input("enter blood group: "),
            "diagnosis": input("enter diagnosis: ")
        }

        patients.append(patient)
        print("patient record succesfully added")
        patient_text = str(patient)
        # corrected: this returns LIST of encrypted RSA chunks
        encrypt = rsa_encrypt_long_message(
            patient_text,
            drpublic
        )
        # corrected: join chunks only for hash and signature
        encrypted_bytes = b"".join(encrypt)
        sha256hash = sha256_hex(
            encrypted_bytes
        )
        signature = rsa_sign_sha256(
            encrypted_bytes,
            drprivate
        )
        timestamp = timestamp_now()
        record = {
            "id": len(records) + 1,
            # corrected: store original LIST so RSA long decrypt works
            "encrypted": encrypt,
            "hash": sha256hash,
            "signature": signature,
            "timestamp": timestamp
        }
        records.append(record)
        print("record finally added")
        print("patient records up to date")
        for patient in patients:
            print(patient)
        for record in records:
            # corrected: long decrypt needs LIST of RSA chunks
            decrypt = rsa_decrypt_long_message(
                record["encrypted"],
                drprivate
            )
            # corrected: join chunks before hashing/verifying
            encrypted_bytes = b"".join(
                record["encrypted"]
            )
            recompute_hash = sha256_hex(
                encrypted_bytes
            )
            integrity = (
                recompute_hash
                == record["hash"]
            )

            verified = rsa_verify_sha256(
                encrypted_bytes,
                record["signature"],
                drpublic
            )
            if integrity and verified:

                # corrected: decode bytes for normal output
                print(decrypt.decode())

                print("verification successful!")

    elif role == "2":
        for record in records:
            print("id: ", record["id"])
            print("encrypted: ", record["encrypted"])
            print("hash: ", record["hash"])
            print("signature: ", record["signature"])
            print("timestamp: ", record["timestamp"])


            # corrected: convert RSA chunk list to bytes for hashing
            encrypted_bytes = b"".join(
                record["encrypted"]
            )
            recompute_sha_hash = sha256_hex(
                encrypted_bytes
            )
            integrity = (
                recompute_sha_hash
                == record["hash"]
            )
            print("integrity: ", integrity)

            verify_Sign = rsa_verify_sha256(
                encrypted_bytes,
                record["signature"],
                drpublic
            )
            print("sign verification: ", verify_Sign)
            print("timestamp: ", timestamp_now())

        print(
            "nurses do not have access to doctors private key so nurses cant decrypt"
        )


    elif role == "3":
        for record in records:
            print("id: ", record["id"])
            print("sha hash: ", record["hash"])
            print("timestamp: ", record["timestamp"])
            # corrected: signature was made on joined encrypted bytes
            encrypted_bytes = b"".join(
                record["encrypted"]
            )
            verifysign = rsa_verify_sha256(
                encrypted_bytes,
                record["signature"],
                drpublic
            )
            if verifysign:
                print("Valid")
            else:
                print("invalid")


        print(
            "admins do not have access to drs private key decryption not allowed"
        )



'''
The only thing you really need to remember from this correction is:

encrypt = rsa_encrypt_long_message(...)

means:

encrypt = LIST of encrypted chunks

So keep that list for:

rsa_decrypt_long_message(encrypt, private_key)

but create:

encrypted_bytes = b"".join(encrypt)

for:

sha256_hex(encrypted_bytes)

rsa_sign_sha256(encrypted_bytes, private_key)

rsa_verify_sha256(encrypted_bytes, signature, public_key)

Do not overwrite:

encrypt = b"".join(encrypt)


'''

'''
doctor
nurse
admin
'''

import hashlib

from datetime import datetime

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


def rsa_generate(bits=2048):

    private_key = RSA.generate(bits)

    public_key = private_key.publickey()

    return public_key, private_key


def rsa_encrypt_bytes(data, public_key):

    if isinstance(data, str):

        data = data.encode()

    cipher = PKCS1_OAEP.new(public_key)

    return cipher.encrypt(data)


def rsa_decrypt_bytes(ciphertext, private_key):

    cipher = PKCS1_OAEP.new(private_key)

    return cipher.decrypt(ciphertext)


def sha256_hex(data):

    if isinstance(data, str):

        data = data.encode()

    return hashlib.sha256(data).hexdigest()


def rsa_sign_sha256(data, private_key):

    if isinstance(data, str):

        data = data.encode()

    digest = SHA256.new(data)

    signature = pkcs1_15.new(private_key).sign(digest)

    return signature


def rsa_verify_sha256(data, signature, public_key):

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


def timestamp_now():

    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


patients = []

records = []


drpublic, drprivate = rsa_generate(2048)


while True:

    print("hospital system")

    print("1. doctor")

    print("2. nurse")

    print("3. admin")

    print("0. exit")


    role = input("enter role: ")


    if role == "1":

        patient = {

            "name": input("Enter name: "),

            "age": input("Enter age: "),

            "gender": input("gender: "),

            "blood group": input("enter blood group: "),

            "diagnosis": input("enter diagnosis: ")

        }


        patients.append(patient)


        print("patient record successfully added")


        patient_text = str(patient)


        # RSA encryption gives normal bytes
        encrypt = rsa_encrypt_bytes(
            patient_text,
            drpublic
        )


        sha256hash = sha256_hex(
            encrypt
        )


        signature = rsa_sign_sha256(
            encrypt,
            drprivate
        )


        timestamp = timestamp_now()


        record = {

            "id": len(records) + 1,

            "encrypted": encrypt,

            "hash": sha256hash,

            "signature": signature,

            "timestamp": timestamp

        }


        records.append(record)


        print("record finally added")

        print("patient records up to date")


        for patient in patients:

            print(patient)


        for record in records:

            recompute_hash = sha256_hex(
                record["encrypted"]
            )


            integrity = (
                recompute_hash
                == record["hash"]
            )


            verified = rsa_verify_sha256(
                record["encrypted"],
                record["signature"],
                drpublic
            )


            if integrity and verified:

                decrypt = rsa_decrypt_bytes(
                    record["encrypted"],
                    drprivate
                )


                print(decrypt.decode())

                print("verification successful!")


    elif role == "2":

        for record in records:

            print("id: ", record["id"])

            print(
                "encrypted: ",
                record["encrypted"]
            )

            print(
                "hash: ",
                record["hash"]
            )

            print(
                "signature: ",
                record["signature"]
            )

            print(
                "timestamp: ",
                record["timestamp"]
            )


            recompute_sha_hash = sha256_hex(
                record["encrypted"]
            )


            integrity = (
                recompute_sha_hash
                == record["hash"]
            )


            print(
                "integrity: ",
                integrity
            )


            verify_sign = rsa_verify_sha256(
                record["encrypted"],
                record["signature"],
                drpublic
            )


            print(
                "sign verification: ",
                verify_sign
            )


            print(
                "timestamp: ",
                timestamp_now()
            )


        print(
            "nurses do not have access to doctors private key so nurses cant decrypt"
        )


    elif role == "3":

        for record in records:

            print(
                "id: ",
                record["id"]
            )

            print(
                "sha hash: ",
                record["hash"]
            )

            print(
                "timestamp: ",
                record["timestamp"]
            )


            verifysign = rsa_verify_sha256(
                record["encrypted"],
                record["signature"],
                drpublic
            )


            if verifysign:

                print("Valid")

            else:

                print("invalid")


        print(
            "admins do not have access to drs private key decryption not allowed"
        )


    elif role == "0":

        break


    else:

        print("invalid role")
