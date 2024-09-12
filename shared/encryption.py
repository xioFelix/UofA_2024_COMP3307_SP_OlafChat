from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import os
import base64
import json
import logging


# RSA key generation
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)


def get_private_key():
    return private_key


# Decrypt AES key using RSA private key
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


# Decrypt the encrypted message using the AES key
def decrypt_message(encrypted_message, rsa_private_key):
    # Convert the message from JSON format
    message_data = json.loads(encrypted_message.decode("utf-8"))

    # Decode the base64 encoded parts
    encrypted_key = base64.b64decode(message_data["encrypted_key"])
    iv = base64.b64decode(message_data["iv"])
    encrypted_content = base64.b64decode(message_data["encrypted_message"])

    # Decrypt the AES key
    aes_key = decrypt_aes_key(encrypted_key, rsa_private_key)

    # Decrypt the message content
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    padded_message = decryptor.update(encrypted_content) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()

    # The decrypted 'message' field may already be a JSON string, so you don't need to parse it again
    decrypted_message = {
        "message": message.decode(),  # Just decode it to a string
        "signature": message_data["signature"],  # Pass the signature
    }

    return decrypted_message  # Return the full structure


# Encrypt AES key using RSA public key
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


# Sign a message with RSA private key
def sign_message(private_key, message, counter):
    # Add the counter to the message to prevent replay attacks
    message["counter"] = counter
    serialized_message = json.dumps(message)

    signature = private_key.sign(
        serialized_message.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("utf-8")


# Verify the signature
def verify_signature(public_key, message, signature):
    try:
        signature_bytes = base64.b64decode(signature)
        serialized_message = json.dumps(message)  # same serialization
        public_key.verify(
            signature_bytes,
            serialized_message.encode("utf-8"),  # use the same serialized string for verification
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


# Encrypt a message with AES, include signature, and return the whole package
def encrypt_message(message, rsa_public_key, signature):
    aes_key = os.urandom(32)
    iv = os.urandom(16)

    encrypted_key = encrypt_aes_key(aes_key, rsa_public_key)

    padder = sym_padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    message_with_signature = {
        "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "encrypted_message": base64.b64encode(encrypted_message).decode("utf-8"),
        "signature": signature,  # Make sure signature is included here
    }
    logging.info(f"---message_with_signature---: {message_with_signature}")

    return json.dumps(message_with_signature).encode("utf-8")
