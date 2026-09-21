import hashlib

from datetime import datetime

from Crypto.Cipher import DES

from Crypto.PublicKey import RSA

from Crypto.Signature import pkcs1_15

from Crypto.Hash import SHA256

from Crypto.Random import get_random_bytes

from Crypto.Util.Padding import pad, unpad



def des_encrypt(plaintext, key, iv=None):

    if isinstance(plaintext, str):

        plaintext = plaintext.encode()

    if iv is None:

        iv = get_random_bytes(8)

    cipher = DES.new(
        key,
        DES.MODE_CBC,
        iv
    )

    encrypted = cipher.encrypt(
        pad(plaintext, DES.block_size)
    )

    return encrypted, iv



def des_decrypt(ciphertext, key, iv):

    cipher = DES.new(
        key,
        DES.MODE_CBC,
        iv
    )

    decrypted = unpad(
        cipher.decrypt(ciphertext),
        DES.block_size
    )

    return decrypted



def rsa_generate(bits=2048):

    private_key = RSA.generate(bits)

    public_key = private_key.publickey()

    return public_key, private_key



def rsa_sign_sha256(data, private_key):

    if isinstance(data, str):

        data = data.encode()

    digest = SHA256.new(data)

    signature = pkcs1_15.new(
        private_key
    ).sign(digest)

    return signature



def rsa_verify_sha256(data, signature, public_key):

    if isinstance(data, str):

        data = data.encode()

    digest = SHA256.new(data)

    try:

        pkcs1_15.new(
            public_key
        ).verify(
            digest,
            signature
        )

        return True

    except (ValueError, TypeError):

        return False



def sha256_hex(data):

    if isinstance(data, str):

        data = data.encode()

    return hashlib.sha256(
        data
    ).hexdigest()



def timestamp_now():

    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )



records = []


student_public, student_private = rsa_generate(2048)


# shared DES key

des_key = get_random_bytes(8)



while True:

    print("\nEDUSECURE")

    print("1. Student")

    print("2. Faculty")

    print("3. HoD")

    print("0. Exit")


    role = input("Enter role: ")



    # =====================================================
    # STUDENT
    # =====================================================

    if role == "1":

        print("1. Upload academic record")

        print("2. View uploaded records")


        choice = input("Enter choice: ")



        if choice == "1":

            filename = input(
                "Enter academic record filename: "
            )


            with open(filename, "rb") as file:

                data = file.read()


            encrypted, iv = des_encrypt(
                data,
                des_key
            )


            # hash encrypted record

            hashvalue = sha256_hex(
                encrypted
            )


            # rsa_sign_sha256 itself hashes encrypted data and signs the hash

            signature = rsa_sign_sha256(
                encrypted,
                student_private
            )


            timestamp = timestamp_now()


            record = {

                "id": len(records) + 1,

                "filename": filename,

                "encrypted": encrypted,

                "hash": hashvalue,

                "signature": signature,

                "iv": iv,

                "timestamp": timestamp

            }


            records.append(record)


            print("record successfully uploaded")


            print(
                "encrypted record: ",
                encrypted.hex()
            )


            print(
                "SHA-256 hash: ",
                hashvalue
            )


            print(
                "signature: ",
                signature.hex()
            )


            print(
                "timestamp: ",
                timestamp
            )



        elif choice == "2":

            if len(records) == 0:

                print("no records available")

                continue


            for record in records:

                print(
                    "id: ",
                    record["id"]
                )

                print(
                    "filename: ",
                    record["filename"]
                )

                print(
                    "encrypted: ",
                    record["encrypted"].hex()
                )

                print(
                    "hash: ",
                    record["hash"]
                )

                print(
                    "timestamp: ",
                    record["timestamp"]
                )



    # =====================================================
    # FACULTY
    # =====================================================

    elif role == "2":

        if len(records) == 0:

            print("no records available")

            continue


        print("available records")


        for record in records:

            print(
                "id: ",
                record["id"],
                "filename: ",
                record["filename"]
            )


        record_id = int(
            input("Enter record id: ")
        )


        selected = None


        for record in records:

            if record["id"] == record_id:

                selected = record

                break


        if selected is None:

            print("invalid record")

            continue


        # recompute hash of encrypted record

        recompute_hash = sha256_hex(
            selected["encrypted"]
        )


        integrity = (
            recompute_hash
            == selected["hash"]
        )


        print(
            "integrity: ",
            integrity
        )


        # verify student signature using public key

        signature_valid = rsa_verify_sha256(
            selected["encrypted"],
            selected["signature"],
            student_public
        )


        print(
            "signature verification: ",
            signature_valid
        )


        verification_time = timestamp_now()


        print(
            "verification timestamp: ",
            verification_time
        )


        # decrypt only if both checks pass

        if integrity and signature_valid:

            decrypted = des_decrypt(
                selected["encrypted"],
                des_key,
                selected["iv"]
            )


            print(
                "decrypted academic record: "
            )


            print(
                decrypted.decode()
            )


            verification_result = {

                "record id": selected["id"],

                "integrity": integrity,

                "signature": signature_valid,

                "timestamp": verification_time

            }


            print(
                "verification result: ",
                verification_result
            )


        else:

            print("verification failed")

            print("decryption not performed")



    # =====================================================
    # HOD
    # =====================================================

    elif role == "3":

        if len(records) == 0:

            print("no records available")

            continue


        for record in records:

            print("\nHOD")


            # HoD only sees hash and timestamp

            print(
                "hash: ",
                record["hash"]
            )


            print(
                "timestamp: ",
                record["timestamp"]
            )


            # verify signature using student public key

            signature_valid = rsa_verify_sha256(
                record["encrypted"],
                record["signature"],
                student_public
            )


            print(
                "signature verification: ",
                signature_valid
            )


        print(
            "HoD cannot decrypt or view academic records"
        )



    elif role == "0":

        break



    else:

        print("invalid role")


'''
 

Question:  

The platform uses DES symmetric encryption for storing sensitive academic records, RSA digital signatures for authenticating users, and SHA-256 hashing to verify record integrity. 

User Roles & Permissions You are tasked with developing a secure education data management system called EduSecure. This system ensures that students’ academic records are stored confidentially, accessed only by authorized users, and verified for authenticity. The system supports three types of users: Students, Faculties, and HoDs, each with specific roles and permissions. 

 

Student: 

Encrypts a student’s academic records (for example: - ISL-5CCE-A2.txt) using DES before uploading. 

Signs the SHA-256 hash of the encrypted record using his/her RSA private key. 

Can view past uploaded records and his/her encrypted/hashed forms with timestamps. 

Faculty: 

Decrypts the student’s records using the shared DES key. 

Verifies RSA signatures of the students to ensure authenticity. 

Computes SHA-256 hash of decrypted records and compares with the stored hash. 

Stores verification reswith ults timestamps. 

HoD: 

Can view only the hashed academic records with timestamps. 

Verifies RSA signatures on stored records for accreditation purposes. 

Access Roles: 

Allow Students to encrypt records with DES, sign using RSA, and upload securely. 

Enable Faculties to decrypt with DES, verify RSA signatures, and hash the records. 

Allow HoDs to view only hashes and verify signatures. 

Task: 

Develop a menu-driven Python program that implements these functionalities using: 

DES symmetric encryption, 

RSA digital signatures, and 

SHA-256 hashing. 

Ensure secure handling of academic records and proper role-based access. Use any file or database structure to store and retrieve the records securely. 

'''
