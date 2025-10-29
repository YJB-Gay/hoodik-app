#!/usr/bin/env python3

import os
import hashlib
from Crypto.Cipher import AES, ChaCha20
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def aes_generate_key():
    return get_random_bytes(32)

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    if isinstance(data, str):
        data = data.encode('utf-8')
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return iv + ciphertext

def aes_decrypt(ciphertext, key):
    if len(ciphertext) < 16:
        raise ValueError("ciphertext too short")
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

def aes_encrypt_string(text, key):
    if isinstance(key, str):
        key_bytes = key.encode('utf-8')
        if len(key_bytes) < 32:
            key_bytes = key_bytes + b'0' * (32 - len(key_bytes))
        else:
            key_bytes = key_bytes[:32]
        key = key_bytes
    encrypted = aes_encrypt(text, key)
    return bytes_to_hex(encrypted)

def aes_decrypt_string(encrypted_hex, key):
    if isinstance(key, str):
        key_bytes = key.encode('utf-8')
        if len(key_bytes) < 32:
            key_bytes = key_bytes + b'0' * (32 - len(key_bytes))
        else:
            key_bytes = key_bytes[:32]
        key = key_bytes
    encrypted = bytes.fromhex(encrypted_hex)
    plaintext = aes_decrypt(encrypted, key)
    return plaintext.decode('utf-8')

def chacha_encrypt(data, key):
    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    if isinstance(data, str):
        data = data.encode('utf-8')
    ciphertext = cipher.encrypt(data)
    return nonce + ciphertext

def chacha_decrypt(ciphertext, key):
    if len(ciphertext) < 12:
        raise ValueError("ciphertext too short")
    nonce = ciphertext[:12]
    ciphertext = ciphertext[12:]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def rsa_encrypt_message(message, public_key_pem):
    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key)
    if isinstance(message, str):
        message = message.encode('utf-8')
    encrypted = cipher.encrypt(message)
    return base64.b64encode(encrypted).decode('utf-8')

def rsa_decrypt_message(private_key_pem, encrypted_b64):
    private_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(private_key)
    encrypted = base64.b64decode(encrypted_b64)
    decrypted = cipher.decrypt(encrypted)
    return decrypted.decode('utf-8')

def rsa_public_from_private(private_key_pem):
    private_key = RSA.import_key(private_key_pem)
    public_key = private_key.publickey()
    return public_key.export_key().decode('utf-8')

def sha256_digest(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()

def bytes_to_hex(data):
    return data.hex()

def bytes_from_hex(hex_str):
    return bytes.fromhex(hex_str)

def crc16_digest(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
    crc ^= 0xFFFF
    return format(crc, 'x')

def string_to_hashed_tokens(text):
    tokens = text.lower().split()
    return [sha256_digest(token) for token in tokens]
