'''
fieldtrack

system design : name : fieldtrack 
consists of sender and reciever

exchange messages using diffie hellman key exchange
affine cipher algorithim

1. key exchange 

sender and reciever establishes a shared key using diffie hellman 
sender and reciever must independelty compute their shared secret and verify if both 
secrets are equal before proceeding

2. encryption

sender enters plaintext
convert plaintext into uppercase and retain only alpha character 
numbers spaces other things discarded

k = shared key 
affine cipher parameter k2 = 2 
k mod 26 == k2 

k1 from the user 

validate k1 by checking gcd(k1, 26) = 1

condition satisfied 
compute multiplicative inverse of k1 modulo 26

k1 is invalid system must discard the value and must not perform enceyptio

enceypt processed plaintext using affine cipher

3. decryption

reciever must verufy that its computes shared key == senderes key

if it doesnt match 
stop decrytyption

set k to recievers shared secret and perdfom same validation 
k mod 26 == k2
validate k1 by checking k1 , 26 gcd is 1

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


def dh_generate_public(p, g, private=None):  # Generate one Diffie-Hellman public/private pair.
    if private is None:  # Generate private value when none is supplied.
        private = random.randint(2, p - 2)  # Choose secret exponent.
    public = pow(g, private, p)  # Compute public value g^private mod p.
    return public, private  # Return public and private values.


def dh_shared_secret(other_public, private, p):  # Compute Diffie-Hellman shared secret.
    return pow(other_public, private, p)  # Raise other side's public value to our private exponent.

def clean_letters(text):  # Remove spaces/punctuation and convert to lowercase.
    return "".join(ch.lower() for ch in text if ch.isalpha())  # Keep only alphabetic characters.



def affine_encrypt(text, a, b):  # Affine encryption: C = (aP + b) mod 26.
    if math.gcd(a, 26) != 1:  # Ensure 'a' is invertible modulo 26.
        raise ValueError("Affine key 'a' must be coprime with 26.")  # Stop for invalid a.
    text = clean_letters(text)  # Normalize plaintext.
    result = ""  # Store ciphertext.
    for ch in text:  # Process each letter.
        p = ord(ch) - ord("a")  # Convert letter to 0-25.
        c = (a * p + b) % 26  # Apply affine formula.
        result += chr(c + ord("a"))  # Convert number back to letter.
    return result  # Return ciphertext.


def affine_decrypt(ciphertext, a, b):  # Affine decryption: P = a^-1(C-b) mod 26.
    a_inv = pow(a, -1, 26)  # Compute inverse of a modulo 26.
    result = ""  # Store plaintext.
    for ch in ciphertext.lower():  # Process each encrypted letter.
        c = ord(ch) - ord("a")  # Convert letter to 0-25.
        p = (a_inv * (c - b)) % 26  # Reverse affine transformation.
        result += chr(p + ord("a"))  # Convert number back to letter.
    return result  # Return plaintext.


# senders side

plaintext = input("enter plaintext: ")
plaintext = "".join(
    ch for ch in plaintext.upper()
    if ch.isalpha()
)
print("plaintext: ", plaintext)
sender_private = 3 
reciever_private = 8
sender_public, sender_private = dh_generate_public(23, 5, sender_private)
reciever_public, reciever_private = dh_generate_public(23, 5, reciever_private)
senders_secret_key = dh_shared_secret(reciever_public, sender_private, 23)
reciever_secret_key = dh_shared_secret(sender_public, reciever_private,23)
if senders_secret_key != reciever_secret_key:
    print("Shared secrets do not match")
else:
    print("shared secrets match")
    k2 = 2
    if senders_secret_key % 26 == k2:
        k1 = int(input("enter k1: "))
        if math.gcd(k1, 26) != 1:  # Ensure 'a' is invertible modulo 26.
                raise ValueError("Affine key 'a' must be coprime with 26.")  # Stop for invalid a.
        else:
            k1_inv = pow(k1, -1, 26)
            print("inverse of k1: ", k1_inv)
            encrypted = affine_encrypt(plaintext, k1, k2)
            print("encrypted: ", encrypted.upper())
    else:
        print("k mod 26 is not equal to k2")
        print("encryption cannot proceed")

    # recievers side 

    if reciever_secret_key % 26 != k2 :
        print("decryption cannot proceed")
    elif math.gcd(k1, 26) != 1:
        print("invalid k1")
        print("decryption cannot proceed")
    else:
        k1_inv = pow(k1, -1, 26)
        print("reciever inverse of k1: ", k1_inv)
        decrypted = affine_decrypt(encrypted, k1, k2)
        print("Decryptedc: ", decrypted.upper())
