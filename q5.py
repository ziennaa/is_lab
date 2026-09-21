'''
Perform a hospital based management system using AES-128, ELGAMAL, RSA. 
Under the following specifications 

Create a file and add content to it

Encrypt the file content using aes and store the encrypted msg in another file

Using rsa encrypt the aes key and store in another file

An authorisation code was given which was to be encrypted using elgamal under the given parameters 

Display the encrypted msg, public key, rsa values

Perform hashing on the encrypted msg of aes.

Check for validity of sender and receiver hashing

If verified, perform decryption and show all the decrypted text , aes key and the decrypted original file content

If integrity failed don't perform decryption and show error output 

For showing integrity failed, modify one character in the aes cipher text and perform hashing on it
This must thore integrity failed since tampering is done to encrypted file

'''
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


# aes 128 
# elgamal
# rsa


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


def elgamal_encrypt_int(m, public_key, k=None):  # Encrypt one integer m where 0 <= m < p.
    p, g, y = public_key  # Unpack ElGamal public parameters.
    if not (0 <= m < p):  # Message must fit modulo p.
        raise ValueError("ElGamal integer message must satisfy 0 <= m < p.")  # Reject too-large integer.
    if k is None:  # Generate ephemeral key when not provided.
        k = random.randint(2, p - 2)  # Choose temporary secret.
    c1 = pow(g, k, p)  # Compute c1=g^k mod p.
    s = pow(y, k, p)  # Compute shared masking value y^k mod p.
    c2 = (m * s) % p  # Mask message to form c2.
    return (c1, c2)  # Return ElGamal ciphertext pair.


def elgamal_decrypt_int(ciphertext, p, x):  # Decrypt one ElGamal integer ciphertext.
    c1, c2 = ciphertext  # Unpack ciphertext pair.
    s = pow(c1, x, p)  # Recompute shared secret.
    s_inv = inverse(s, p)  # Find modular inverse of shared secret.
    return (c2 * s_inv) % p  # Recover original integer.


def elgamal_encrypt_text(text, public_key):  # Encrypt text character-by-character for simple lab use.
    return [elgamal_encrypt_int(ord(ch), public_key) for ch in text]  # Encrypt each Unicode code point.


def elgamal_decrypt_text(cipher_list, p, x):  # Decrypt list of ElGamal character ciphertexts.
    return "".join(chr(elgamal_decrypt_int(pair, p, x)) for pair in cipher_list)  # Recover every character.


def sha256_hex(data):  # Compute SHA-256 in hexadecimal form.
    if isinstance(data, str):  # Convert text to bytes.
        data = data.encode()  # UTF-8 encode.
    return hashlib.sha256(data).hexdigest()  # Return 64-character SHA-256 hex string.


hpub, hpriv = rsa_generate(2048)
aes_key = get_random_bytes(16)
with open("sample.txt", "w") as file:
    file.write("abcd\nefgh\nijkl\nmnop\nqrst\nuvwx\nyzab")

with open("sample.txt", "rb") as file:
    data = file.read()

encrypted, iv = aes_cbc_encrypt(data, aes_key)

with open("encrypted_content.bin", "wb") as file:
    file.write(iv + encrypted)

encrypt_aes_key = rsa_encrypt_bytes(aes_key, hpub)

with open("encrypted_key.bin", "wb") as file:
    file.write(encrypt_aes_key)

authorisation_code = 1234 
p = 7919
g = 2
y = 5678
public_key = (p, g, y)
code_encrypted = elgamal_encrypt_int(authorisation_code, public_key)
print("ElGamal encrypted authorisation code: ", code_encrypted)

print("ElGamal public key: ", public_key)

print("AES encrypted message: ", encrypted)

print("RSA encrypted AES key: ", encrypt_aes_key)

print("RSA public key: ", hpub)


senderhashh = sha256_hex(encrypted)

# reciever side

with open("encrypted_content.bin", "rb") as file:
    recieved_data = file.read()

r_iv = recieved_data[:16]
r_encrypted = recieved_data[16:]
rhash = sha256_hex(r_encrypted)
print("reciever hash: ", rhash)

integrity = senderhashh == rhash
print("integrity: ", integrity)
if integrity:
    print("integrity verified")
    with open("encrypted_key.bin", "rb") as file:
        recieved_encrypted_key = file.read()
    decrypted_aes_key =rsa_decrypt_bytes(recieved_encrypted_key, hpriv)
    print("decrypted aes key: ", decrypted_aes_key.hex())
    decrypted_content = aes_cbc_decrypt(r_encrypted, decrypted_aes_key, r_iv)
    print("original decrypted file content: ", decrypted_content.decode())
    with open("decrypted_content.txt", "wb") as file:
        file.write(decrypted_content)
else:
    print("integrity failed")
    print("decryption not performed")

tampered = bytearray(r_encrypted)
tampered[0] = tampered[0] ^ 1
tampered = bytes(tampered)
tampered_hash = sha256_hex(tampered)
print("after tampering")
print("original sender hash: ", senderhashh)
print("tampered hash: ", tampered_hash)
tampered_integrity = senderhashh == tampered_hash
print("integrity_Tampered: ", tampered_integrity)
if tampered_integrity:
    decrypted_content = aes_cbc_decrypt(tampered, decrypted_aes_key, r_iv)
    print(decrypted_content.decode())
else:
    print("integrity failed")
    print("not performing decryoptuon")
