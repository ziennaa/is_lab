import hashlib

from datetime import datetime

from Crypto.Cipher import AES, PKCS1_OAEP

from Crypto.PublicKey import RSA

from Crypto.Signature import pkcs1_15

from Crypto.Hash import SHA256

from Crypto.Util.Padding import pad, unpad



def aes_cbc_encrypt(plaintext, key, iv):

    if isinstance(plaintext, str):

        plaintext = plaintext.encode()

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv
    )

    ciphertext = cipher.encrypt(
        pad(plaintext, AES.block_size)
    )

    return ciphertext



def aes_cbc_decrypt(ciphertext, key, iv):

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv
    )

    plaintext = unpad(
        cipher.decrypt(ciphertext),
        AES.block_size
    )

    return plaintext



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


patient_public, patient_private = rsa_generate(2048)



while True:

    print("\nMEDISECURE")

    print("1. Patient")

    print("2. Doctor")

    print("3. Auditor")

    print("0. Exit")


    role = input("Enter role: ")



    if role == "1":

        print("1. Upload medical record")

        print("2. View uploaded records")


        choice = input("Enter choice: ")



        if choice == "1":

            filename = input(
                "Enter .txt filename: "
            )


            with open(filename, "rb") as file:

                data = file.read()


            aes_key_hex = input(
                "Enter AES-128 key in hex: "
            )


            aes_key = bytes.fromhex(
                aes_key_hex
            )


            if len(aes_key) != 16:

                print("AES-128 key must be 16 bytes")

                continue


            iv_hex = input(
                "Enter IV in hex: "
            )


            iv = bytes.fromhex(
                iv_hex
            )


            if len(iv) != 16:

                print("AES IV must be 16 bytes")

                continue


            encrypted = aes_cbc_encrypt(
                data,
                aes_key,
                iv
            )


            hashvalue = sha256_hex(
                encrypted
            )


            signature = rsa_sign_sha256(
                hashvalue,
                patient_private
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
                "hash: ",
                hashvalue
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


        aes_key_hex = input(
            "Enter shared AES key in hex: "
        )


        aes_key = bytes.fromhex(
            aes_key_hex
        )


        if len(aes_key) != 16:

            print("AES-128 key must be 16 bytes")

            continue


        recompute_hash = sha256_hex(
            selected["encrypted"]
        )


        integrity = (
            recompute_hash
            == selected["hash"]
        )


        signature_valid = rsa_verify_sha256(
            selected["hash"],
            selected["signature"],
            patient_public
        )


        print(
            "integrity: ",
            integrity
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


        if integrity and signature_valid:

            try:

                decrypted = aes_cbc_decrypt(
                    selected["encrypted"],
                    aes_key,
                    selected["iv"]
                )


                print(
                    "decrypted medical record: "
                )

                print(
                    decrypted.decode()
                )


            except ValueError:

                print("wrong AES key")

                print("decryption failed")


        else:

            print(
                "verification failed"
            )

            print(
                "decryption not performed"
            )



    elif role == "3":

        if len(records) == 0:

            print("no records available")

            continue


        for record in records:

            print("\nAUDITOR")


            print(
                "filename: ",
                record["filename"]
            )

            print(
                "hash: ",
                record["hash"]
            )

            print(
                "timestamp: ",
                record["timestamp"]
            )


            signature_valid = rsa_verify_sha256(
                record["hash"],
                record["signature"],
                patient_public
            )


            print(
                "signature verification: ",
                signature_valid
            )


        print(
            "auditor cannot decrypt or view plaintext records"
        )



    elif role == "0":

        break



    else:

        print("invalid role")
