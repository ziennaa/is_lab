
import socket  # Communicate with server.
import json  # Convert report dictionary to JSON.
import hashlib  # Calculate SHA-256 hash.
import random  # Generate Schnorr signing values.
from datetime import datetime  # Generate report timestamp.

from Crypto.Cipher import AES, PKCS1_OAEP  # AES and RSA encryption.
from Crypto.PublicKey import RSA  # Import server RSA public key.
from Crypto.Random import get_random_bytes  # Generate random AES key and IV.
from Crypto.Util.Padding import pad  # Add AES padding.


def aes_cbc_encrypt(plaintext, key, iv=None):  # Encrypt report using AES-CBC.
    if isinstance(plaintext, str):  # Check whether plaintext is a string.
        plaintext = plaintext.encode()  # Convert string into bytes.

    if iv is None:  # Generate IV if not provided.
        iv = get_random_bytes(16)  # Create random 16-byte IV.

    cipher = AES.new(key, AES.MODE_CBC, iv)  # Create AES-CBC cipher.
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))  # Encrypt padded report.

    return ciphertext, iv  # Return encrypted report and IV.


def rsa_encrypt_bytes(data, public_key):  # Encrypt AES key using RSA.
    cipher = PKCS1_OAEP.new(public_key)  # Create RSA-OAEP cipher.
    return cipher.encrypt(data)  # Return encrypted AES key.


def sha256_hex(data):  # Calculate SHA-256 hash.
    if isinstance(data, str):  # Check whether input is text.
        data = data.encode()  # Convert text into bytes.
    return hashlib.sha256(data).hexdigest()  # Return hexadecimal hash.


def schnorr_generate(p=23, q=11, g=2, x=None):  # Generate demo Schnorr keys.
    if x is None:  # Generate private key if not provided.
        x = random.randint(1, q - 1)  # Choose private signing key.

    y = pow(g, x, p)  # Calculate Schnorr public key.
    return (p, q, g, y), x  # Return public and private keys.


def schnorr_sign(message, public_params, private_x):  # Sign message using Schnorr.
    p, q, g, y = public_params  # Read Schnorr parameters.
    k = random.randint(1, q - 1)  # Generate random signing nonce.
    r = pow(g, k, p)  # Calculate Schnorr commitment.

    digest = hashlib.sha256((str(r) + "|" + message).encode()).digest()  # Hash message and commitment.
    e = int.from_bytes(digest, "big") % q  # Calculate challenge.
    s = (k + private_x * e) % q  # Calculate response.

    return (e, s)  # Return Schnorr signature.


def send_json(conn, data):  # Send JSON data to server.
    conn.sendall((json.dumps(data) + "\n").encode())  # Send serialized JSON.


def receive_json(conn):  # Receive JSON data from server.
    return json.loads(conn.makefile("r").readline())  # Read and decode JSON.


# STEP 1: Connect to server.
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP socket.
client.connect(("127.0.0.1", 5000))  # Connect to server port 5000.


# STEP 2: Receive server's RSA public key.
server_data = receive_json(client)  # Receive RSA public key.
rsa_pub = RSA.import_key(server_data["rsa_public_key"])  # Import server public key.


# STEP 3: Take report details from user.
report_id = input("Enter Report ID: ").strip()  # Read report ID.
severity = int(input("Enter Severity (integer): "))  # Read severity.
timestamp = datetime.now().isoformat(timespec="seconds")  # Generate report timestamp.


# STEP 4: Create report dictionary.
report = {  # Store all report fields.
    "report_id": report_id,  # Store report ID.
    "severity": severity,  # Store severity integer.
    "timestamp": timestamp  # Store timestamp.
}

report_data = json.dumps(report, sort_keys=True)  # Convert report to JSON.
print("Original report:", report_data)  # Display report before encryption.


# STEP 5: Generate AES-128 key.
aes_key = get_random_bytes(16)  # Generate 16-byte AES key.


# STEP 6: Encrypt report using AES-128.
encrypted_report, iv = aes_cbc_encrypt(report_data, aes_key)  # Encrypt report.


# STEP 7: Encrypt AES key using server's RSA public key.
encrypted_aes_key = rsa_encrypt_bytes(aes_key, rsa_pub)  # Protect AES key using RSA.


# STEP 8: Generate SHA-256 hash of original report.
report_hash = sha256_hex(report_data)  # Calculate report hash.


# STEP 9: Prepare encrypted data for server.
body = {  # Store encrypted report details.
    "ciphertext": encrypted_report.hex(),  # AES encrypted report.
    "iv": iv.hex(),  # AES initialization vector.
    "encrypted_key": encrypted_aes_key.hex(),  # RSA encrypted AES key.
    "sha256": report_hash  # SHA-256 of original report.
}


# STEP 10: Generate Schnorr signing keys.
schnorr_pub, schnorr_priv = schnorr_generate()  # Generate Schnorr key pair.


# STEP 11: Sign encrypted report package.
signed_message = json.dumps(body, sort_keys=True, separators=(",", ":"))  # Create signed message.
signature = schnorr_sign(signed_message, schnorr_pub, schnorr_priv)  # Sign message.


# STEP 12: Prepare final packet.
packet = {  # Combine encrypted report and signature.
    "body": body,  # Store encrypted report information.
    "signature": list(signature),  # Store Schnorr signature.
    "schnorr_public": list(schnorr_pub)  # Store Schnorr public parameters.
}


# STEP 13: Send packet to server.
send_json(client, packet)  # Transmit encrypted report.


# STEP 14: Receive server result.
response = receive_json(client)  # Receive verification and deadline result.
print("Server response:", response["status"])  # Display server response.


client.close()  # Close client connection.
