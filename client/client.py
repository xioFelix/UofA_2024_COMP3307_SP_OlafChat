import socket
import os
import json
import logging
import threading
import base64
import time
from shared.encryption import (
    load_or_generate_private_key,
    load_public_key,
    serialize_public_key,
    encrypt_message,
    decrypt_message,
    sign_message,
    verify_signature,
    aes_encrypt,
    aes_decrypt,
    generate_aes_key,
    rsa_encrypt,
    rsa_decrypt,
)
from getpass import getpass

logging.basicConfig(level=logging.INFO)


class Client:
    """
    Chat client that connects to the server and communicates with other users.
    """

    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.socket = None
        self.private_key = None
        self.server_public_key = None
        self.username = None
        self.logged_in = False
        self.user_public_keys = {}  # Store other users' public keys
        self.shared_keys = {}  # Store shared keys with other users
        self.lock = threading.Lock()
        self.message_queue = []  # Queue for outgoing messages

    def connect(self):
        """
        Connect to the server and perform initial handshake.
        """
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.server_ip, self.server_port))
        logging.info(f"Connected to server at {self.server_ip}:{self.server_port}")

        # Receive server's public key
        server_public_key_pem = self.socket.recv(8192)
        self.server_public_key = load_public_key(server_public_key_pem)
        logging.info("Received server public key.")

    def register_or_login(self):
        """
        Prompt the user to register or login.
        """
        self.username = input("Enter your username: ")

        # Use username to specify unique private key filename
        key_filename = f"{self.username}_private_key.pem"
        self.private_key = load_or_generate_private_key(key_filename)

        choice = input("Do you want to (r)egister or (l)ogin? ")
        if choice.lower() == "r":
            message = {
                "type": "register",
                "username": self.username,
                "public_key": serialize_public_key(
                    self.private_key.public_key()
                ).decode("utf-8"),
            }
        elif choice.lower() == "l":
            message = {
                "type": "login",
                "username": self.username,
                "public_key": serialize_public_key(
                    self.private_key.public_key()
                ).decode("utf-8"),
            }
        else:
            print("Invalid choice.")
            self.socket.close()
            return False

        self.socket.sendall(json.dumps(message).encode("utf-8"))

        # Receive and decrypt the response from the server
        response_data = self.socket.recv(8192)
        decrypted_response = decrypt_message(
            response_data.decode("utf-8"), self.private_key
        )
        response = json.loads(decrypted_response)

        if response["status"] == "success":
            self.logged_in = True
            print(response["message"])
            return True
        else:
            print(response["message"])
            self.socket.close()
            return False

    def send_message(self, content):
        """
        Send a message to the server with signature and encryption.
        """
        # Sign the message
        signature = sign_message(self.private_key, content)
        message = {"content": content, "signature": signature}
        message_json = json.dumps(message)

        # Encrypt the message
        encrypted_message = encrypt_message(message_json, self.server_public_key)
        with self.lock:
            self.socket.sendall(encrypted_message.encode("utf-8"))

    def receive_messages(self):
        """
        Receive messages from the server.
        """
        while self.logged_in:
            try:
                data = self.socket.recv(8192)
                if not data:
                    break
                decrypted_data = decrypt_message(data.decode("utf-8"), self.private_key)
                response = json.loads(decrypted_data)
                msg_type = response.get("type")
                if msg_type == "user_list":
                    users = response.get("users")
                    print(f"\nOnline users: {users}")
                elif msg_type == "public_key":
                    username = response.get("username")
                    public_key_pem = response.get("public_key")
                    self.user_public_keys[username] = public_key_pem
                elif msg_type == "shared_key":
                    sender = response.get("from")
                    encrypted_shared_key_b64 = response.get("encrypted_shared_key")
                    self.receive_shared_key(sender, encrypted_shared_key_b64)
                elif msg_type == "private_message":
                    sender = response.get("from")
                    encrypted_message = response.get("message")
                    # Decrypt the message content
                    message = self.decrypt_private_message(sender, encrypted_message)
                    print(f"\n[Private] {sender}: {message}")
                elif msg_type == "broadcast":
                    sender = response.get("from")
                    message = response.get("message")
                    print(f"\n[Broadcast] {sender}: {message}")
                elif msg_type == "file_data":
                    filename = response.get("filename")
                    file_data_b64 = response.get("file_data")
                    self.receive_file(filename, file_data_b64)
                else:
                    print(f"\nServer response: {response}")
                # Re-display the prompt
                print(
                    f"Enter command or message ('/help' for commands): ",
                    end="",
                    flush=True,
                )
            except Exception as e:
                logging.error(f"Error receiving message: {e}")
                continue  # Continue to listen for messages

    def start(self):
        """
        Start the client application.
        """
        self.connect()
        if not self.register_or_login():
            return

        # Start the thread to receive messages
        receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        receive_thread.start()

        try:
            while self.logged_in:
                print(
                    f"Enter command or message ('/help' for commands): ",
                    end="",
                    flush=True,
                )
                message = input()
                if message.lower() == "quit":
                    self.logged_in = False
                    self.socket.close()
                    break
                elif message.lower() == "/list":
                    # Request online users list
                    content_data = {"type": "list_users"}
                    content = json.dumps(content_data)
                    self.send_message(content)
                elif message.startswith("/all "):
                    # Send broadcast message
                    message_body = message[5:]
                    content_data = {"type": "broadcast", "body": message_body}
                    content = json.dumps(content_data)
                    self.send_message(content)
                elif message.startswith("/msg "):
                    # Send private message: /msg <username> <message>
                    parts = message.split(" ", 2)
                    if len(parts) >= 3:
                        recipient = parts[1]
                        message_body = parts[2]
                        self.send_private_message(recipient, message_body)
                    else:
                        print("Usage: /msg <username> <message>")
                elif message.startswith("/upload "):
                    # Upload file: /upload <filename>
                    parts = message.split(" ", 1)
                    if len(parts) == 2:
                        filename = parts[1]
                        self.upload_file(filename)
                    else:
                        print("Usage: /upload <filename>")
                elif message.startswith("/download "):
                    # Download file: /download <filename>
                    parts = message.split(" ", 1)
                    if len(parts) == 2:
                        filename = parts[1]
                        self.download_file(filename)
                    else:
                        print("Usage: /download <filename>")
                elif message.lower() == "/help":
                    self.show_help()
                else:
                    print("Unknown command or message format.")
                    self.show_help()
        except KeyboardInterrupt:
            self.logged_in = False
            self.socket.close()
        finally:
            receive_thread.join()
            logging.info("Client shutdown.")

    def send_private_message(self, recipient, message_body):
        """
        Send a private message to another user.
        """
        # Check if a shared key already exists
        if recipient not in self.shared_keys:
            # Establish a shared key with the recipient
            shared_key = self.establish_shared_key(recipient)
            if not shared_key:
                print(f"Failed to establish shared key with {recipient}.")
                return
            self.shared_keys[recipient] = shared_key
            # Wait for the recipient to receive and store the shared key
            time.sleep(
                1
            )  # Simple delay; consider implementing a confirmation mechanism
        else:
            shared_key = self.shared_keys[recipient]

        # Encrypt the message using the shared key
        iv, encrypted_message = aes_encrypt(shared_key, message_body.encode())
        encrypted_message_b64 = base64.b64encode(iv + encrypted_message).decode("utf-8")

        content_data = {
            "type": "private_message",
            "to": recipient,
            "message": encrypted_message_b64,
        }
        content = json.dumps(content_data)
        self.send_message(content)

    def decrypt_private_message(self, sender, encrypted_message_b64):
        """
        Decrypt a received private message.
        """
        # Check if a shared key exists
        if sender not in self.shared_keys:
            print(f"No shared key with {sender}. Cannot decrypt message.")
            return "<Encrypted Message>"

        shared_key = self.shared_keys[sender]

        # Decrypt the message
        encrypted_data = base64.b64decode(encrypted_message_b64)
        iv = encrypted_data[:16]
        encrypted_message = encrypted_data[16:]
        plaintext = aes_decrypt(shared_key, iv, encrypted_message)
        return plaintext.decode("utf-8")

    def establish_shared_key(self, recipient):
        """
        Establish a shared key with another user.
        """
        # Check if we already have the recipient's public key
        if recipient not in self.user_public_keys:
            # Request the recipient's public key from the server
            self.request_user_public_key(recipient)
            # Wait for the public key to be received
            time.sleep(
                1
            )  # Simple delay; consider implementing a confirmation mechanism
            if recipient not in self.user_public_keys:
                print(f"Failed to get public key for {recipient}.")
                return None

        recipient_public_key_pem = self.user_public_keys[recipient]
        recipient_public_key = load_public_key(recipient_public_key_pem.encode("utf-8"))

        # Generate a shared key
        shared_key = generate_aes_key()

        # Encrypt the shared key with the recipient's public key
        encrypted_shared_key = rsa_encrypt(recipient_public_key, shared_key)

        # Send the encrypted shared key to the recipient
        encrypted_shared_key_b64 = base64.b64encode(encrypted_shared_key).decode(
            "utf-8"
        )
        content_data = {
            "type": "shared_key",
            "to": recipient,
            "encrypted_shared_key": encrypted_shared_key_b64,
        }
        content = json.dumps(content_data)
        self.send_message(content)

        # Store the shared key locally
        return shared_key

    def request_user_public_key(self, username):
        """
        Request another user's public key from the server.
        """
        content_data = {"type": "get_public_key", "username": username}
        content = json.dumps(content_data)
        self.send_message(content)

    def receive_shared_key(self, sender, encrypted_shared_key_b64):
        """
        Receive and decrypt a shared key from another user.
        """
        encrypted_shared_key = base64.b64decode(encrypted_shared_key_b64)
        shared_key = rsa_decrypt(self.private_key, encrypted_shared_key)
        # Store the shared key
        self.shared_keys[sender] = shared_key
        print(f"\nEstablished shared key with {sender}.")

    def upload_file(self, filename):
        """
        Upload a file to the server.
        """
        try:
            with open(filename, "rb") as f:
                file_data = f.read()
            file_data_b64 = base64.b64encode(file_data).decode("utf-8")
            content_data = {
                "type": "upload",
                "filename": os.path.basename(filename),
                "file_data": file_data_b64,
            }
            content = json.dumps(content_data)
            self.send_message(content)
            print(f"Uploading file {filename}...")
        except FileNotFoundError:
            print(f"File {filename} not found.")

    def download_file(self, filename):
        """
        Request to download a file from the server.
        """
        content_data = {"type": "download", "filename": filename}
        content = json.dumps(content_data)
        self.send_message(content)
        print(f"Requesting file {filename}...")

    def receive_file(self, filename, file_data_b64):
        """
        Receive a file from the server and save it locally.
        """
        file_data = base64.b64decode(file_data_b64)
        save_path = os.path.join("client_files", filename)
        os.makedirs("client_files", exist_ok=True)
        with open(save_path, "wb") as f:
            f.write(file_data)
        print(f"\nFile {filename} downloaded and saved to client_files/{filename}.")

    def show_help(self):
        """
        Display help information for available commands.
        """
        help_text = """
Available commands:
/list                     - Show online users.
/all <message>            - Send a broadcast message.
/msg <user> <message>     - Send a private message to a user.
/upload <filename>        - Upload a file to the server.
/download <filename>      - Download a file from the server.
/help                     - Show this help message.
quit                      - Exit the chat.
"""
        print(help_text)


if __name__ == "__main__":
    client = Client("127.0.0.1", 8080)
    client.start()
