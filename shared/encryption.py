import os
import base64
import json
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def load_or_generate_private_key(key_path):
    """
    Load an existing RSA private key from the specified path,
    or generate a new one if it doesn't exist.
    """
    if os.path.exists(key_path):
        with open(key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None
            )
        logging.info(f"Loaded existing private key from {key_path}.")
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(key_path, "wb") as key_file:
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            key_file.write(pem)
        logging.info(f"Generated new private key and saved to {key_path}.")
    return private_key


def load_public_key(pem_data):
    """
    Load an RSA public key from PEM data.
    """
    public_key = serialization.load_pem_public_key(pem_data)
    return public_key


def serialize_public_key(public_key):
    """
    Serialize an RSA public key to PEM format.
    """
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_key_pem


def rsa_encrypt(public_key, data):
    """
    Encrypt data using RSA public key encryption.
    """
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return encrypted


def rsa_decrypt(private_key, encrypted_data):
    """
    Decrypt data using RSA private key decryption.
    """
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return decrypted


def aes_encrypt(aes_key, plaintext):
    """
    Encrypt plaintext using AES-GCM symmetric encryption.
    """
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(16)
    encrypted = aesgcm.encrypt(iv, plaintext, None)
    return iv, encrypted


def aes_decrypt(aes_key, iv, ciphertext):
    """
    Decrypt ciphertext using AES-GCM symmetric decryption.
    """
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext


def generate_aes_key():
    """
    Generate a random AES key.
    """
    return os.urandom(32)


def sign_message(private_key, message):
    """
    Sign a message using RSA private key.
    """
    signature = private_key.sign(
        message.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("utf-8")


def verify_signature(public_key, message, signature):
    """
    Verify a message signature using RSA public key.
    """
    try:
        signature_bytes = base64.b64decode(signature)
        public_key.verify(
            signature_bytes,
            message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        logging.info("Signature verified successfully.")
        return True
    except Exception as e:
        logging.error(f"Signature verification failed: {e}")
        return False


def encrypt_message(message, recipient_public_key):
    """
    Encrypt a message using the recipient's public key and AES symmetric encryption.
    """
    aes_key = generate_aes_key()
    iv, encrypted_message = aes_encrypt(aes_key, message.encode())
    encrypted_key = rsa_encrypt(recipient_public_key, aes_key)
    message_package = {
        "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "encrypted_message": base64.b64encode(encrypted_message).decode("utf-8"),
    }
    return json.dumps(message_package)


def decrypt_message(message_package_json, private_key):
    """
    Decrypt a received message using the recipient's private key and AES symmetric decryption.
    """
    message_package = json.loads(message_package_json)
    encrypted_key = base64.b64decode(message_package["encrypted_key"])
    iv = base64.b64decode(message_package["iv"])
    encrypted_message = base64.b64decode(message_package["encrypted_message"])

    aes_key = rsa_decrypt(private_key, encrypted_key)
    plaintext = aes_decrypt(aes_key, iv, encrypted_message)
    return plaintext.decode("utf-8")
