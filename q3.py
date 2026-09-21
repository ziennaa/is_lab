'''
secure vault


3 roles
1. client 
2. lawyer
3. compilance officer

des in cbc mode for encrypt and decrypt
sha 256 for data integrity verification 
elgamal digital signature for authenticantion and verification

client

1. provide confidential record
2. encrypt record using des in cbc mode
3. generate an iv and use it during encryption 
4. calcualte shaa 256 hash of encrypted data
5. generate elgamal digital signature using clients private key
6. display thte follwoing
ciphertrexct
ive 
sha 256 hash value 
timestamp
7. store the ciphertext , iv hashvallue signature and timestamp in the file fo 
SecureVault – Secure Record Management System

Design and implement an application named "SecureVault" for securely storing, authenticating, accessing, and auditing confidential client records. The application must have three roles: Client, Lawyer, and Compliance Officer.

The application must use:
1. DES in CBC mode for encryption and decryption.
2. SHA-256 for data integrity verification.
3. ElGamal Digital Signature for authentication and verification.

CLIENT:

The Client should:
1. Enter/provide a confidential record.
2. Encrypt the record using DES in CBC mode.
3. Generate an IV and use it during encryption.
4. Calculate the SHA-256 hash of the encrypted data.
5. Generate an ElGamal digital signature using the client's private key.
6. Display the following:
   - Ciphertext
   - IV
   - SHA-256 hash value
   - ElGamal signature
   - Timestamp
7. Store the ciphertext, IV, hash value, signature, and timestamp in a file for future verification and access.

LAWYER:

The Lawyer should:
1. Read the stored ciphertext, IV, hash value, signature, and timestamp from the file.
2. Recalculate the SHA-256 hash and compare it with the stored hash value.
3. Verify the ElGamal digital signature using the client's public key.
4. Display the hash verification and signature verification status.
5. Only if the hash and signature verification are successful, decrypt the ciphertext using DES in CBC mode.
6. Display the recovered plaintext record.
7. Store the verification/access status along with a timestamp.

If the integrity or signature verification fails, the Lawyer must not decrypt or access the plaintext.

COMPLIANCE OFFICER:

The Compliance Officer should:
1. Access the stored encrypted record and its associated security metadata.
2. Verify the SHA-256 hash to check whether the stored data has been modified.
3. Verify the ElGamal digital signature using the client's public key.
4. Display the hash verification and signature verification status.
5. Record the verification results along with a timestamp.
6. Generate a Compliance Report containing the verification status and relevant metadata.
7. The Compliance Officer must NOT decrypt the ciphertext or access the client's plaintext record.

The application should maintain proper role-based access, ensuring that:
- The Client can create and securely store records.
- The Lawyer can verify and decrypt records after successful authentication.
- The Compliance Officer can independently audit the record's integrity and authenticity without accessing the plaintext.

The system should clearly display all relevant security information and verification results.
'''
import math  # Gives gcd() and other basic math functions.
import random  # Used for ElGamal random values.
import hashlib  # Used for SHA-256 hashing.
import pickle  # Used to save/load dictionary/list directly from file.

from datetime import datetime  # Used for timestamp.

from Crypto.Cipher import DES  # DES encryption.
from Crypto.Random import get_random_bytes  # Random DES key and IV.
from Crypto.Util.Padding import pad, unpad  # DES padding.
from Crypto.Util.number import inverse  # Modular inverse for ElGamal.


# ============================================================
# DES ENCRYPTION
# ============================================================

def des_encrypt(plaintext, key8, iv=None):

    if isinstance(plaintext, str):

        plaintext = plaintext.encode()

    if len(key8) != 8:

        raise ValueError("DES key must be exactly 8 bytes.")

    if iv is None:

        iv = get_random_bytes(8)

    cipher = DES.new(
        key8,
        DES.MODE_CBC,
        iv
    )

    ciphertext = cipher.encrypt(
        pad(plaintext, DES.block_size)
    )

    return ciphertext, iv


# ============================================================
# DES DECRYPTION
# ============================================================

def des_decrypt(ciphertext, key8, iv):

    cipher = DES.new(
        key8,
        DES.MODE_CBC,
        iv
    )

    plaintext = unpad(
        cipher.decrypt(ciphertext),
        DES.block_size
    )

    return plaintext


# ============================================================
# SHA-256
# ============================================================

def sha256_hex(data):

    if isinstance(data, str):

        data = data.encode()

    return hashlib.sha256(data).hexdigest()


# ============================================================
# ELGAMAL KEY GENERATION
# ============================================================

def elgamal_generate(p=7919, g=2, x=None):

    if x is None:

        x = random.randint(
            2,
            p - 2
        )

    y = pow(
        g,
        x,
        p
    )

    return (p, g, y), x


# ============================================================
# ELGAMAL SIGNATURE
# ============================================================

def elgamal_sign(message, p, g, private_x):

    digest = int.from_bytes(
        hashlib.sha256(message.encode()).digest(),
        "big"
    ) % (p - 1)

    while True:

        k = random.randint(
            2,
            p - 2
        )

        if math.gcd(k, p - 1) == 1:

            break

    r = pow(
        g,
        k,
        p
    )

    k_inverse = pow(
        k,
        -1,
        p - 1
    )

    s = (
        (digest - private_x * r)
        * k_inverse
    ) % (p - 1)

    return r, s


# ============================================================
# ELGAMAL SIGNATURE VERIFICATION
# ============================================================

def elgamal_verify(message, signature, public_key):

    p, g, y = public_key

    r, s = signature

    if not (0 < r < p):

        return False

    digest = int.from_bytes(
        hashlib.sha256(message.encode()).digest(),
        "big"
    ) % (p - 1)

    left = pow(
        g,
        digest,
        p
    )

    right = (
        pow(y, r, p)
        * pow(r, s, p)
    ) % p

    return left == right


# ============================================================
# TIMESTAMP
# ============================================================

def timestamp_now():

    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


# ============================================================
# SAVE RECORDS TO FILE
# ============================================================

def save_records(records):

    with open("records.dat", "wb") as file:

        pickle.dump(
            records,
            file
        )


# ============================================================
# LOAD RECORDS FROM FILE
# ============================================================

def load_records():

    try:

        with open("records.dat", "rb") as file:

            records = pickle.load(file)

            return records

    except FileNotFoundError:

        return []


# ============================================================
# MAIN PROGRAM
# ============================================================


# Generate Client ElGamal keys.

client_public, client_private = elgamal_generate()

p, g, y = client_public


# DES key used for confidential records.

des_key = get_random_bytes(8)


while True:

    print("\n======================")
    print("SECURE VAULT")
    print("======================")

    print("1. Client")
    print("2. Lawyer")
    print("3. Compliance Officer")
    print("0. Exit")

    role = input("Enter role: ")


    # ========================================================
    # CLIENT
    # ========================================================

    if role == "1":

        records = load_records()


        confidential_record = input(
            "Enter confidential record: "
        )


        # DES-CBC encrypt confidential record.

        encrypted, iv = des_encrypt(
            confidential_record,
            des_key
        )


        # SHA-256 hash of encrypted data.

        hash256 = sha256_hex(
            encrypted
        )


        # Sign the SHA-256 hash using Client private key.

        signature = elgamal_sign(
            hash256,
            p,
            g,
            client_private
        )


        # Create timestamp.

        timestamp = timestamp_now()


        # Store everything in dictionary.

        record = {

            "id": len(records) + 1,

            "ciphertext": encrypted,

            "iv": iv,

            "hash": hash256,

            "signature": signature,

            "timestamp": timestamp

        }


        # Add record to list.

        records.append(record)


        # Save whole list into file.

        save_records(records)


        # Display required values.

        print("\nRecord stored successfully")

        print("Record ID:", record["id"])

        print(
            "Ciphertext:",
            encrypted.hex()
        )

        print(
            "IV:",
            iv.hex()
        )

        print(
            "SHA-256:",
            hash256
        )

        print(
            "ElGamal Signature:",
            signature
        )

        print(
            "Timestamp:",
            timestamp
        )


    # ========================================================
    # LAWYER
    # ========================================================

    elif role == "2":

        # Read records FROM FILE.

        records = load_records()


        if len(records) == 0:

            print("No records available")

            continue


        for record in records:

            print("\n----------------------")

            print(
                "Record ID:",
                record["id"]
            )

            print(
                "Ciphertext:",
                record["ciphertext"].hex()
            )

            print(
                "IV:",
                record["iv"].hex()
            )

            print(
                "Stored Hash:",
                record["hash"]
            )

            print(
                "Signature:",
                record["signature"]
            )

            print(
                "Timestamp:",
                record["timestamp"]
            )


            # Recompute SHA-256 of ciphertext.

            new_hash = sha256_hex(
                record["ciphertext"]
            )


            # Compare hashes.

            integrity = (
                new_hash
                == record["hash"]
            )


            # Verify ElGamal signature.

            signature_valid = elgamal_verify(

                record["hash"],

                record["signature"],

                client_public
            )


            print(
                "Integrity:",
                integrity
            )

            print(
                "Signature Valid:",
                signature_valid
            )


            # Decrypt ONLY if both checks pass.

            if integrity and signature_valid:

                decrypted = des_decrypt(

                    record["ciphertext"],

                    des_key,

                    record["iv"]
                )


                print(
                    "Plaintext Record:",
                    decrypted.decode()
                )


            else:

                print(
                    "Verification failed"
                )

                print(
                    "Record will NOT be decrypted"
                )


    # ========================================================
    # COMPLIANCE OFFICER
    # ========================================================

    elif role == "3":

        # Read records FROM FILE.

        records = load_records()


        if len(records) == 0:

            print("No records available")

            continue


        for record in records:

            print("\n----------------------")
            print("COMPLIANCE AUDIT")


            # Compliance Officer can access
            # encrypted data and metadata.

            print(
                "Record ID:",
                record["id"]
            )

            print(
                "Ciphertext:",
                record["ciphertext"].hex()
            )

            print(
                "Stored Hash:",
                record["hash"]
            )

            print(
                "Signature:",
                record["signature"]
            )

            print(
                "Original Timestamp:",
                record["timestamp"]
            )


            # Recompute SHA-256.

            new_hash = sha256_hex(
                record["ciphertext"]
            )


            # Check integrity.

            integrity = (
                new_hash
                == record["hash"]
            )


            # Verify Client signature.

            signature_valid = elgamal_verify(

                record["hash"],

                record["signature"],

                client_public
            )


            print(
                "Hash Verification:",
                integrity
            )

            print(
                "Signature Verification:",
                signature_valid
            )


            # Verification timestamp.

            verification_time = timestamp_now()


            # Generate Compliance Report.

            compliance_report = {

                "record id":
                    record["id"],

                "stored hash":
                    record["hash"],

                "hash verification":
                    integrity,

                "signature verification":
                    signature_valid,

                "record timestamp":
                    record["timestamp"],

                "verification timestamp":
                    verification_time

            }


            print("\nCOMPLIANCE REPORT")

            print(compliance_report)


            # Store Compliance Report in file.

            with open(
                "compliance_report.txt",
                "a"
            ) as file:

                file.write(
                    str(compliance_report)
                )

                file.write("\n")


        # IMPORTANT:
        # Compliance Officer never decrypts.

        print(
            "\nCompliance Officer cannot "
            "decrypt or access plaintext"
        )


    # ========================================================
    # EXIT
    # ========================================================

    elif role == "0":

        print("Exiting SecureVault")

        break


    # ========================================================
    # INVALID INPUT
    # ========================================================

    else:

        print("Invalid role")
