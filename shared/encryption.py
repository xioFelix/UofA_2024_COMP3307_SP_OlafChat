# shared/encryption.py

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os
import logging


def load_or_generate_private_key(filename):
    """
    Load an existing private key from a PEM file, or generate a new one if not found.
    """
    if os.path.exists(filename):
        with open(filename, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        logging.debug(f"Loaded existing private key from {filename}.")
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        with open(filename, "wb") as key_file:
            key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        logging.debug(f"Generated and saved new private key to {filename}.")
    return private_key


def load_public_key(pem_data):
    """
    Load a public key from PEM data.
    """
    return serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )


def serialize_public_key(public_key):
    """
    Serialize a public key to PEM format.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def sign_message(private_key, message):
    """
    Sign a message using RSA private key.
    """
    signature = private_key.sign(
        message.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # Encode signature in base64 for JSON serialization
    return base64.b64encode(signature).decode("utf-8")


def verify_signature(public_key, message, signature_b64):
    """
    Verify a message signature using RSA public key.
    """
    try:
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        logging.debug("Signature verification succeeded.")
        return True
    except Exception as e:
        logging.error(f"Signature verification failed: {e}")
        return False


def encrypt_message(message, public_key):
    """
    Encrypt a message using RSA public key.
    """
    encrypted = public_key.encrypt(
        message.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Encode encrypted data in base64 for JSON serialization
    return base64.b64encode(encrypted).decode("utf-8")


def decrypt_message(encrypted_b64, private_key):
    """
    Decrypt an encrypted message using RSA private key.
    """
    encrypted = base64.b64decode(encrypted_b64)
    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode("utf-8")


def generate_aes_key():
    """
    Generate a random 256-bit AES key.
    """
    return os.urandom(32)


def aes_encrypt(key, plaintext):
    """
    Encrypt plaintext using AES CBC mode.
    Returns the IV and ciphertext.
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # Pad plaintext to block size (16 bytes)
    padding_length = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + bytes([padding_length] * padding_length)
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return iv, ciphertext


def aes_decrypt(key, iv, ciphertext):
    """
    Decrypt ciphertext using AES CBC mode.
    Returns the plaintext.
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    # Remove padding
    padding_length = padded_plaintext[-1]
    plaintext = padded_plaintext[:-padding_length]
    return plaintext


def rsa_encrypt(public_key, data):
    """
    Encrypt data using RSA public key.
    """
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


def rsa_decrypt(private_key, encrypted_data):
    """
    Decrypt data using RSA private key.
    """
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted
