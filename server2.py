
import socket  # Create client-server communication.
import json  # Convert dictionaries to JSON.
import hashlib  # Calculate SHA-256 hashes.
from datetime import datetime  # Check submission deadline.

from Crypto.PublicKey import RSA  # Generate RSA keys.
from Crypto.Cipher import AES, PKCS1_OAEP  # AES and RSA encryption.
from Crypto.Util.Padding import unpad  # Remove AES padding.


def rsa_generate(bits=2048):  # Generate RSA public and private keys.
    private_key = RSA.generate(bits)  # Generate private key.
    public_key = private_key.publickey()  # Generate public key.
    return public_key, private_key  # Return both keys.


def rsa_decrypt_bytes(ciphertext, private_key):  # Decrypt encrypted AES key.
    cipher = PKCS1_OAEP.new(private_key)  # Create RSA decryption object.
    return cipher.decrypt(ciphertext)  # Return original AES key.


def aes_cbc_decrypt(ciphertext, key, iv):  # Decrypt report using AES.
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Create AES-CBC cipher.
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)  # Decrypt and remove padding.
    return plaintext  # Return original report bytes.


def sha256_hex(data):  # Calculate SHA-256 hash.
    if isinstance(data, str):  # Check if data is a string.
        data = data.encode()  # Convert string to bytes.
    return hashlib.sha256(data).hexdigest()  # Return hash in hexadecimal.


def schnorr_verify(message, signature, public_params):  # Verify Schnorr signature.
    p, q, g, y = public_params  # Read Schnorr public parameters.
    e, s = signature  # Read signature components.

    r = (pow(g, s, p) * pow(pow(y, e, p), -1, p)) % p  # Reconstruct commitment.
    digest = hashlib.sha256((str(r) + "|" + message).encode()).digest()  # Hash commitment and message.
    e_new = int.from_bytes(digest, "big") % q  # Calculate expected challenge.

    return e == e_new  # Return True if signature matches.


def send_json(conn, data):  # Send JSON message to client.
    conn.sendall((json.dumps(data) + "\n").encode())  # Send serialized JSON.


def receive_json(conn):  # Receive JSON message from client.
    return json.loads(conn.makefile("r").readline())  # Read one JSON line.


# STEP 1: Generate RSA keys on the server.
rsa_pub, rsa_priv = rsa_generate(2048)  # Server keeps private key.


# STEP 2: Set the submission deadline.
deadline = input("Enter deadline (YYYY-MM-DD HH:MM:SS): ")  # Get deadline.
deadline = datetime.strptime(deadline, "%Y-%m-%d %H:%M:%S")  # Convert string to datetime.


# STEP 3: Create server socket.
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP socket.
server.bind(("127.0.0.1", 5000))  # Bind to localhost port 5000.
server.listen(1)  # Wait for one client.

print("Server waiting for client...")  # Display server status.


# STEP 4: Accept client connection.
conn, addr = server.accept()  # Connect to client.
print("Client connected!")  # Confirm connection.


# STEP 5: Send RSA public key to client.
send_json(conn, {"rsa_public_key": rsa_pub.export_key().decode()})  # Send public key only.


# STEP 6: Receive encrypted report.
packet = receive_json(conn)  # Receive client's packet.
received_at = datetime.now()  # Record server receipt time.

body = packet["body"]  # Get encrypted report information.
signature = tuple(packet["signature"])  # Get Schnorr signature.
schnorr_pub = tuple(packet["schnorr_public"])  # Get Schnorr public parameters.


# STEP 7: Reconstruct signed message.
signed_message = json.dumps(body, sort_keys=True, separators=(",", ":"))  # Recreate signed JSON.


# STEP 8: Verify Schnorr signature.
valid = schnorr_verify(signed_message, signature, schnorr_pub)  # Verify signature.

print("Schnorr signature valid:", valid)  # Display verification result.

if valid:  # Continue only if signature is valid.

    # STEP 9: Convert hexadecimal data back to bytes.
    encrypted_key = bytes.fromhex(body["encrypted_key"])  # Read encrypted AES key.
    encrypted_report = bytes.fromhex(body["ciphertext"])  # Read AES ciphertext.
    iv = bytes.fromhex(body["iv"])  # Read AES initialization vector.

    # STEP 10: Decrypt AES key using server RSA private key.
    aes_key = rsa_decrypt_bytes(encrypted_key, rsa_priv)  # Recover AES-128 key.

    # STEP 11: Decrypt the report using AES-128.
    decrypted = aes_cbc_decrypt(encrypted_report, aes_key, iv)  # Recover report.

    # STEP 12: Verify SHA-256 hash.
    new_hash = sha256_hex(decrypted)  # Compute hash of decrypted data.
    hash_valid = new_hash == body["sha256"]  # Compare with client hash.

    print("SHA-256 valid:", hash_valid)  # Display hash verification.

    if hash_valid:  # Display report only when both checks succeed.

        report = json.loads(decrypted.decode())  # Convert decrypted JSON into dictionary.

        print("\n===== VERIFIED REPORT =====")  # Display report heading.
        print("Report ID:", report["report_id"])  # Display report ID.
        print("Severity:", report["severity"])  # Display severity.
        print("Timestamp:", report["timestamp"])  # Display report timestamp.

        # STEP 13: Check server submission deadline.
        if received_at <= deadline:  # Compare actual receipt time with deadline.
            status = "ON TIME"  # Report received before deadline.
        else:
            status = "LATE SUBMISSION"  # Report received after deadline.

        print("Submission Status:", status)  # Display submission status.
        send_json(conn, {"status": status})  # Send status to client.

    else:
        print("Hash verification FAILED!")  # Reject changed report.
        send_json(conn, {"status": "Hash verification failed"})  # Notify client.

else:
    print("Signature verification FAILED!")  # Reject invalid signature.
    send_json(conn, {"status": "Signature verification failed"})  # Notify client.


conn.close()  # Close client connection.
server.close()  # Close server socket.
