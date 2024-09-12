import socket
import os
import json
import logging
from shared.encryption import encrypt_message, sign_message
from cryptography.hazmat.primitives import serialization

# Enable detailed logging for debugging
logging.basicConfig(level=logging.INFO)


class Client:
    def __init__(self, server_ip, server_port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((server_ip, server_port))
        self.private_key = self.load_or_generate_private_key()
        self.server_public_key = self.receive_public_key()
        self.counter = 0
        self.send_hello()

    def load_or_generate_private_key(self):
        if os.path.exists("client_private_key.pem"):
            with open("client_private_key.pem", "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(), password=None
                )
                logging.info("Loaded existing private key.")
        else:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            with open("client_private_key.pem", "wb") as key_file:
                pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                key_file.write(pem)
            logging.info("Generated new private key and saved it.")
        return private_key

    def receive_public_key(self):
        pem_data = self.sock.recv(1024)
        public_key = serialization.load_pem_public_key(pem_data)
        logging.info(f"Received server public key: {pem_data.decode('utf-8')}")
        return public_key

    def send_hello(self):
        self.counter += 1
        hello_message = {
            "type": "hello",
            "public_key": self.private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8"),
        }
        logging.info(f"Sending hello message: {hello_message}")
        self.sock.send(json.dumps(hello_message).encode())

    def send_message(self, message_type, data):
        self.counter += 1
        json_message = {"type": message_type, "data": data, "counter": self.counter}
        serialized_message = json.dumps(json_message)

        logging.info(f"Serialized message for signing: {serialized_message}")

        # Generate the signature
        signature = sign_message(self.private_key, json_message, self.counter)
        logging.info(f"Generated signature: {signature}")

        # Encrypt the message and include the signature
        encrypted_message = encrypt_message(
            serialized_message, self.server_public_key, signature
        )
        logging.info(f"Encrypted message: {encrypted_message.hex()}")

        # Send the encrypted message
        self.sock.send(encrypted_message)

    def start(self):
        while True:
            message = input("Enter message: ")
            if message.lower() == "quit":
                logging.info("Client disconnected.")
                break
            try:
                self.send_message("chat", {"message": message})
            except Exception as e:
                logging.error(f"Error sending message: {e}")
                break

        self.sock.close()


if __name__ == "__main__":
    client = Client("127.0.0.1", 8080)
    client.start()
