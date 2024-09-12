import socket
import logging
import json
from cryptography.hazmat.primitives import serialization
from shared.encryption import get_private_key, decrypt_message, verify_signature

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

private_key = get_private_key()


def handle_client(client_sock):
    logging.info("Handling new client connection")

    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    client_sock.send(public_key_pem)
    logging.info(f"Sent public key to client:\n{public_key_pem.decode('utf-8')}")
    client_public_key = None

    while True:
        try:
            message = client_sock.recv(4096)
            if not message:
                logging.info("Client disconnected")
                break

            if client_public_key is None:
                decoded_message = json.loads(message.decode())
                logging.info(f"Received message: {decoded_message}")

                if decoded_message["type"] == "hello":
                    client_public_key = serialization.load_pem_public_key(
                        decoded_message["public_key"].encode()
                    )
                    logging.info("Received client's public key")
            else:
                logging.info(f"Received encrypted message: {message.hex()}")
                decrypted_message = decrypt_message(message, private_key)

                logging.info(f"Decrypted message: {decrypted_message}")

                try:
                    # Decrypted message may already be a dictionary, so no need to parse again
                    if isinstance(decrypted_message, dict):
                        logging.info("Decrypted message is already a dictionary.")
                    else:
                        decrypted_message = json.loads(decrypted_message)

                    if "signature" not in decrypted_message:
                        logging.error("Missing 'signature' in decrypted message")
                        continue

                    signature = decrypted_message["signature"]
                    data_to_verify = json.loads(decrypted_message["message"])

                    logging.info(f"Verifying signature: {signature}")

                    if not verify_signature(
                        client_public_key, data_to_verify, signature
                    ):
                        logging.error(
                            "Signature verification failed. Rejecting message."
                        )
                        continue

                    if data_to_verify["type"] == "chat":
                        logging.info(
                            f"Received chat message: {data_to_verify['data']['message']}"
                        )
                except json.JSONDecodeError as e:
                    logging.error(f"Failed to decode decrypted message: {e}")

        except Exception as e:
            logging.error(f"Error decrypting or parsing message: {e}")

    client_sock.close()
    logging.info("Closed client connection")


def start_server():
    logging.info("Starting server...")
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("0.0.0.0", 8080))
    server_sock.listen(5)
    logging.info("Server started and listening on port 8080")

    try:
        while True:
            client_sock, addr = server_sock.accept()
            logging.info(f"Accepted connection from {addr}")
            handle_client(client_sock)
    except KeyboardInterrupt:
        logging.info("Shutting down server...")
    finally:
        server_sock.close()
        logging.info("Server socket closed.")


if __name__ == "__main__":
    start_server()
