from client.encryption import (
    rsa_encrypt,
    aes_encrypt,
    generate_aes_key,
    serialize_public_key,
)
from cryptography.hazmat.primitives.serialization import load_pem_public_key


# Client side encryption for sending messages
def send_encrypted_message(server_public_key_pem, message):
    # Load the server's public key
    server_public_key = load_pem_public_key(server_public_key_pem)

    # Generate an AES key for this session
    aes_key = generate_aes_key()

    # Encrypt the message with AES
    iv, encrypted_message = aes_encrypt(aes_key, message.encode())

    # Encrypt the AES key with the server's RSA public key
    encrypted_aes_key = rsa_encrypt(server_public_key, aes_key)

    # Send both the encrypted AES key and the encrypted message
    return encrypted_aes_key, iv, encrypted_message


import time

def send_message_with_timestamp(server_public_key_pem, message):
    # Add a timestamp to the message
    timestamp = int(time.time())
    full_message = f"{timestamp}:{message}"

    # Encrypt the full message
    return send_encrypted_message(server_public_key_pem, full_message)
