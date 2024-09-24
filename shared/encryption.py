# shared/encryption.py

import os
import base64
import json
import logging
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def load_or_generate_private_key(filename):
    """
    Load an existing RSA private key from a file, or generate a new one if it doesn't exist.
    """
    if os.path.exists(filename):
        with open(filename, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
        logging.info(f"Loaded existing private key from {filename}.")
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,  # As per protocol specification
        )
        with open(filename, "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        logging.info(f"Generated new private key and saved to {filename}.")
    return private_key


def load_public_key(pem_data):
    """
    Load a public key from PEM-encoded data.
    """
    public_key = serialization.load_pem_public_key(pem_data)
    return public_key


def serialize_public_key(public_key):
    """
    Serialize a public key to PEM format.
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem


def sign_data(private_key, data, counter):
    """
    Sign data with the private key using RSA-PSS.
    """
    logging.debug(f"Signing data with counter {counter}: {data}")
    # Combine data and counter into a single message
    message = {
        "data": data,
        "counter": counter
    }
    # Serialize the message to JSON with consistent separators and sorted keys
    message_bytes = json.dumps(message, separators=(',', ':'), sort_keys=True).encode('utf-8')
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32,  # Salt length is 32 bytes as per the protocol
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode('utf-8')


def verify_data_signature(public_key, data, counter, signature_b64):
    """
    Verify the signature of data using the public key.
    """
    signature = base64.b64decode(signature_b64)
    message = {
        "data": data,
        "counter": counter
    }
    message_bytes = json.dumps(message, separators=(',', ':'), sort_keys=True).encode('utf-8')
    try:
        public_key.verify(
            signature,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32,  # Salt length is 32 bytes
            ),
            hashes.SHA256(),
        )
        logging.debug("Signature verification successful.")
        return True
    except Exception as e:
        logging.error(f"Signature verification failed: {e}")
        return False


def rsa_encrypt(public_key, plaintext):
    """
    Encrypt plaintext using RSA public key with OAEP padding.
    """
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext


def rsa_decrypt(private_key, ciphertext):
    """
    Decrypt ciphertext using RSA private key with OAEP padding.
    """
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext


def generate_aes_key():
    """
    Generate a 256-bit AES key.
    """
    return os.urandom(32)  # 256-bit key as per protocol


def aes_gcm_encrypt(key, iv, plaintext):
    """
    Encrypt plaintext using AES-GCM.
    """
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag  # Authentication tag
    return ciphertext, tag


def aes_gcm_decrypt(key, iv, ciphertext, tag):
    """
    Decrypt ciphertext using AES-GCM.
    """
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
    ).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


def encrypt_message(data, receiver_public_key):
    """
    Encrypt the message data using AES-GCM and encrypt the AES key with receiver's RSA public key.
    """
    # Generate AES key and IV
    aes_key = generate_aes_key()
    iv = os.urandom(16)  # 16 bytes IV as per protocol

    # Serialize data to JSON and encode to bytes
    plaintext = json.dumps(data, separators=(',', ':'), sort_keys=True).encode('utf-8')
    logging.debug(f"Plaintext to encrypt: {plaintext}")

    # Encrypt the plaintext using AES-GCM
    ciphertext, tag = aes_gcm_encrypt(aes_key, iv, plaintext)
    logging.debug(f"Encrypted ciphertext: {base64.b64encode(ciphertext).decode('utf-8')}")

    # Encrypt the AES key using receiver's RSA public key
    encrypted_key = rsa_encrypt(receiver_public_key, aes_key)

    # Construct the encrypted message
    encrypted_message = {
        'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
    }
    return json.dumps(encrypted_message)


def decrypt_message(encrypted_message_json, private_key):
    """
    Decrypt the message using own RSA private key and AES-GCM.
    """
    logging.debug(f"Decrypting message: {encrypted_message_json}")
    try:
        encrypted_message = json.loads(encrypted_message_json)

        # Decode the components
        encrypted_key = base64.b64decode(encrypted_message['encrypted_key'])
        iv = base64.b64decode(encrypted_message['iv'])
        tag = base64.b64decode(encrypted_message['tag'])
        ciphertext = base64.b64decode(encrypted_message['ciphertext'])

        # Decrypt the AES key using own RSA private key
        aes_key = rsa_decrypt(private_key, encrypted_key)

        # Decrypt the ciphertext using AES-GCM
        plaintext = aes_gcm_decrypt(aes_key, iv, ciphertext, tag)

        # Deserialize the plaintext JSON
        data = json.loads(plaintext.decode('utf-8'))
        return data
    except Exception as e:
        logging.error(f"Error decrypting message: {e}")
        raise


def compute_fingerprint(public_key_pem):
    """
    Compute SHA-256 fingerprint of the public key.
    """
    fingerprint = sha256(public_key_pem).hexdigest()
    return fingerprint
