from server.encryption import rsa_decrypt, aes_decrypt
from cryptography.hazmat.primitives.serialization import load_pem_private_key


# Server side decryption for receiving messages
def receive_encrypted_message(
    server_private_key_pem, encrypted_aes_key, iv, encrypted_message
):
    # Load the server's private key
    server_private_key = load_pem_private_key(server_private_key_pem, password=None)

    # Decrypt the AES key using the server's private RSA key
    aes_key = rsa_decrypt(server_private_key, encrypted_aes_key)

    # Decrypt the message using the decrypted AES key
    message = aes_decrypt(aes_key, iv, encrypted_message)

    return message.decode()


def receive_message_with_timestamp(
    server_private_key_pem,
    encrypted_aes_key,
    iv,
    encrypted_message,
    last_received_timestamp,
):
    # Decrypt the full message
    full_message = receive_encrypted_message(
        server_private_key_pem, encrypted_aes_key, iv, encrypted_message
    )

    # Extract timestamp and message
    timestamp_str, message = full_message.split(":", 1)
    timestamp = int(timestamp_str)

    # Check if the message is a replay (timestamp should be greater than the last received one)
    if timestamp > last_received_timestamp:
        return message, timestamp
    else:
        raise ValueError("Replay attack detected")
