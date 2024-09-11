from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import os

# RSA key generation (in actual application, the key should be pre-generated and safely stored)
# In this demonstration, suppose you already have the private key of the server and the public key of the client.

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# 将private_key导出，以便在server.py中使用
def get_private_key():
    return private_key

# The function of decrypting the AES key
def decrypt_aes_key(encrypted_key, rsa_private_key):
    aes_key = rsa_private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return aes_key

# The function of decrypting messages
def decrypt_message(encrypted_message, rsa_private_key):
    encrypted_key = encrypted_message[
        :256
    ]  # Assume that the length of the RSA key is 2048 bits (256 bytes)
    iv = encrypted_message[256:272]  # Extract IV (assuming 16 bytes)
    encrypted_content = encrypted_message[272:]  # The rest is encrypted messages.

    # Decrypt the AES key
    aes_key = decrypt_aes_key(encrypted_key, rsa_private_key)

    # Use the decrypted AES key to decrypt the message
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    padded_message = decryptor.update(encrypted_content) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    return message.decode()

# Newly added function to encrypt the AES key
def encrypt_aes_key(aes_key, rsa_public_key):
    encrypted_key = rsa_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return encrypted_key

# Newly added functions for encrypting messages
def encrypt_message(message, rsa_public_key):
    aes_key = os.urandom(32)  # Generate a random AES key
    iv = os.urandom(16)  # Generate random IV

    # Encrypt the AES key
    encrypted_key = encrypt_aes_key(aes_key, rsa_public_key)

    # Use AES to encrypt messages
    padder = sym_padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    return (
        encrypted_key + iv + encrypted_message
    )  # Return the encrypted AES key, IV and encrypted message
