# client.py

import traceback
import socket
import threading
import logging
import json
import base64
import os
import ssl
import requests
from shared.encryption import (
    load_or_generate_private_key,
    serialize_public_key,
    load_public_key,
    sign_data,
    verify_data_signature,
    encrypt_message,
    decrypt_message,
    rsa_encrypt,
    rsa_decrypt,
    generate_aes_key,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    compute_fingerprint,
)

# Configure logging
logging.basicConfig(level=logging.DEBUG)


class Client:
    """
    The main client class that handles connection to the server and user interaction.
    """

    def __init__(self, server_ip="127.0.0.1", server_port=8080):
        self.server_ip = server_ip
        self.server_port = server_port
        self.socket = None
        self.username = None
        self.private_key = None
        self.public_key_pem = None
        self.server_public_key = None
        self.fingerprint = None
        self.counter = 0
        self.lock = threading.Lock()
        self.logged_in = False
        self.last_received_counters = {}  # {sender_fingerprint: counter}

        # User data
        self.user_public_keys = {}  # {fingerprint: public_key_pem}
        self.user_fingerprints = {}  # {fingerprint: username}
        self.user_servers = {}      # {fingerprint: server_address}

    def start(self):
        """
        Start the client, connect to the server, and handle user input.
        """
        if not self.connect():
            return

        threading.Thread(target=self.receive_messages).start()
        self.logged_in = True

        print("\nType '/help' for a list of commands.\n")

        while self.logged_in:
            try:
                user_input = input()
                if user_input.strip() == "":
                    continue
                if user_input.startswith("/"):
                    self.handle_command(user_input)
                else:
                    self.send_public_message(user_input)
            except EOFError:
                # Handle Ctrl+D
                self.logout()
                break
            except Exception as e:
                logging.error(f"Error in main loop: {e}")
                traceback.print_exc()

    def connect(self):
        """
        Connect to the server and perform handshake.
        """
        try:
            # Create an unverified SSL context (Insecure, for testing only)
            context = ssl._create_unverified_context()

            # Connect to server
            sock = socket.create_connection((self.server_ip, self.server_port))
            self.socket = context.wrap_socket(sock, server_hostname=self.server_ip)
            logging.info(f"Connected to server at {self.server_ip}:{self.server_port}")

            # Receive server public key
            server_public_key_pem = self.socket.recv(8192)
            self.server_public_key = load_public_key(server_public_key_pem)
            logging.info("Received server public key.")

            # Load or generate client's private key
            self.username = input("Enter your username: ")
            key_filename = f"{self.username}_private_key.pem"
            self.private_key = load_or_generate_private_key(key_filename)
            self.public_key_pem = serialize_public_key(self.private_key.public_key()).decode("utf-8")
            self.fingerprint = compute_fingerprint(self.public_key_pem.encode('utf-8'))

            # Send hello message
            data = {
                "type": "hello",
                "public_key": self.public_key_pem,
                "username": self.username,
            }
            self.counter += 1
            signature = sign_data(self.private_key, data, self.counter)
            message = {
                "data": data,
                "counter": self.counter,
                "signature": signature,
            }
            encrypted_message = encrypt_message(message, self.server_public_key)
            self.send_raw_message(encrypted_message.encode("utf-8"))

            logging.info(f"Sent hello message to server.")
            return True
        except Exception as e:
            logging.error(f"Failed to connect to server: {e}")
            traceback.print_exc()
            return False

    def send_raw_message(self, message_bytes):
        """
        Send a raw message with length prefix.
        """
        message_length = len(message_bytes)
        with self.lock:
            # Send the length of the message first (4 bytes, big-endian)
            self.socket.sendall(message_length.to_bytes(4, byteorder='big'))
            # Send the message itself
            self.socket.sendall(message_bytes)

    def receive_messages(self):
        while self.logged_in:
            try:
                encrypted_message = self.recv_message()
                if not encrypted_message:
                    logging.debug("Server disconnected.")
                    break

                logging.debug(f"Received encrypted message: {encrypted_message}")

                # Decrypt the message
                message = decrypt_message(encrypted_message.decode('utf-8'), self.private_key)
                logging.debug(f"Decrypted message: {message}")

                data = message.get("data")
                counter = message.get("counter")
                signature = message.get("signature")

                # Get sender's fingerprint
                sender_fingerprint = data.get("from", "server")

                # Get sender's public key
                if sender_fingerprint == "server":
                    sender_public_key = self.server_public_key
                else:
                    sender_public_key_pem = self.user_public_keys.get(sender_fingerprint)
                    if sender_public_key_pem:
                        sender_public_key = load_public_key(sender_public_key_pem.encode('utf-8'))
                    else:
                        logging.warning(f"Unknown sender fingerprint: {sender_fingerprint}")
                        continue

                # Verify signature
                is_valid_signature = verify_data_signature(sender_public_key, data, counter, signature)
                logging.debug(f"Signature valid: {is_valid_signature}")
                if not is_valid_signature:
                    logging.warning("Signature verification failed.")
                    continue

                # Check counter to prevent replay attacks
                last_counter = self.last_received_counters.get(sender_fingerprint, 0)
                logging.debug(f"Received counter: {counter}, Last counter: {last_counter}")
                if counter <= last_counter:
                    logging.warning(f"Replay attack detected from {sender_fingerprint}. Message discarded.")
                    continue
                else:
                    self.last_received_counters[sender_fingerprint] = counter

                msg_type = data.get("type")
                logging.debug(f"Message type: {msg_type}")
                if msg_type == "public_chat":
                    self.handle_public_chat(data)
                elif msg_type == "chat":
                    self.handle_chat(data)
                elif msg_type == "client_list":
                    self.handle_client_list(data)
                else:
                    logging.warning(f"Unknown message type from server: {msg_type}")
            except Exception as e:
                logging.error(f"Error receiving message: {e}")
                traceback.print_exc()
                self.logged_in = False
                break

    def recv_message(self):
        # Read message length (4 bytes)
        raw_msglen = self.recvall(4)
        if not raw_msglen:
            return None
        msglen = int.from_bytes(raw_msglen, byteorder='big')
        # Read the message data
        return self.recvall(msglen)

    def recvall(self, n):
        data = b''
        while len(data) < n:
            packet = self.socket.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def handle_command(self, command_input):
        """
        Handle user commands.
        """
        parts = command_input.strip().split()
        command = parts[0]
        args = parts[1:]

        if command == "/list":
            self.request_client_list()
        elif command == "/msg":
            if len(args) < 2:
                print("Usage: /msg <fingerprint> <message>")
            else:
                recipient = args[0]
                message = ' '.join(args[1:])
                self.send_chat_message([recipient], message)
        elif command == "/upload":
            if len(args) < 1:
                print("Usage: /upload <filename>")
            else:
                filename = args[0]
                self.upload_file(filename)
        elif command == "/download":
            if len(args) < 1:
                print("Usage: /download <file_url>")
            else:
                file_url = args[0]
                self.download_file(file_url)
        elif command == "/help":
            self.show_help()
        elif command == "quit":
            self.logout()
        else:
            print("Unknown command. Type '/help' for a list of commands.")

    def send_message(self, data):
        """
        Sign and send a message to the server.
        """
        self.counter += 1
        signature = sign_data(self.private_key, data, self.counter)
        message = {
            "data": data,
            "counter": self.counter,
            "signature": signature,
        }
        encrypted_message = encrypt_message(message, self.server_public_key)
        self.send_raw_message(encrypted_message.encode("utf-8"))

    def send_public_message(self, message_text):
        """
        Send a public chat message.
        """
        data = {
            "type": "public_chat",
            "sender": self.fingerprint,
            "message": message_text,
        }
        self.send_message(data)
        logging.debug("Sent public chat message.")

    def send_chat_message(self, recipients, message_body):
        """
        Send a private chat message to recipients.
        """
        # Generate AES key and IV
        aes_key = generate_aes_key()
        iv = os.urandom(16)  # 16 bytes IV

        # Build participants list
        participants = [self.fingerprint] + recipients

        # Encrypt the message content
        chat_content = {
            "participants": participants,
            "message": message_body,
        }

        # Serialize chat_content
        chat_json = json.dumps(chat_content, separators=(',', ':'), sort_keys=True).encode('utf-8')

        # Encrypt chat_content, get ciphertext and tag
        cipher_text, tag = aes_gcm_encrypt(aes_key, iv, chat_json)

        # Encrypt the AES key with each recipient's public key
        symm_keys = []
        destination_servers = []
        for recipient_fingerprint in recipients:
            recipient_public_key_pem = self.user_public_keys.get(recipient_fingerprint)
            if recipient_public_key_pem:
                recipient_public_key = load_public_key(recipient_public_key_pem.encode("utf-8"))
                encrypted_key = rsa_encrypt(recipient_public_key, aes_key)
                symm_keys.append(base64.b64encode(encrypted_key).decode("utf-8"))
                # Get recipient's server address
                recipient_server_address = self.user_servers.get(recipient_fingerprint, f"{self.server_ip}:{self.server_port}")
                destination_servers.append(recipient_server_address)
            else:
                print(f"Unknown recipient fingerprint: {recipient_fingerprint}")
                return

        # Build the message, include tag
        content_data = {
            "type": "chat",
            "destination_servers": destination_servers,
            "iv": base64.b64encode(iv).decode("utf-8"),
            "tag": base64.b64encode(tag).decode("utf-8"),
            "symm_keys": symm_keys,
            "chat": base64.b64encode(cipher_text).decode("utf-8"),
            "participants": participants,
        }

        self.send_message(content_data)
        logging.debug(f"Sent chat message to {recipients}")

    def handle_chat(self, data):
        """
        Handle received chat message.
        """
        iv_b64 = data.get("iv")
        symm_keys_b64 = data.get("symm_keys")
        chat_b64 = data.get("chat")
        tag_b64 = data.get("tag")
        participants = data.get("participants")

        # Decode iv, tag, cipher_text
        iv = base64.b64decode(iv_b64)
        tag = base64.b64decode(tag_b64)
        cipher_text = base64.b64decode(chat_b64)

        # Find own index in participants (subtract sender)
        try:
            recipient_index = participants.index(self.fingerprint) - 1
        except ValueError:
            logging.warning("This message is not intended for this client.")
            return

        # Get corresponding symm_key
        symm_key_enc_b64 = symm_keys_b64[recipient_index]
        symm_key_enc = base64.b64decode(symm_key_enc_b64)
        aes_key = rsa_decrypt(self.private_key, symm_key_enc)

        # Decrypt message
        plaintext = aes_gcm_decrypt(aes_key, iv, cipher_text, tag)

        # Parse chat_content
        chat_content = json.loads(plaintext.decode('utf-8'))
        message_text = chat_content.get("message")
        sender_fingerprint = chat_content.get("participants")[0]
        sender_username = self.user_fingerprints.get(sender_fingerprint, sender_fingerprint)

        print(f"\n[Private] {sender_username}: {message_text}")

    def handle_public_chat(self, data):
        """
        Handle received public chat message.
        """
        sender_fingerprint = data.get("sender")
        message_text = data.get("message")
        sender_username = self.user_fingerprints.get(sender_fingerprint, sender_fingerprint)
        print(f"\n[Public] {sender_username}: {message_text}")

    def request_client_list(self):
        """
        Request the client list from the server.
        """
        data = {
            "type": "client_list_request",
        }
        self.send_message(data)
        logging.debug("Requested client list")

    def handle_client_list(self, data):
        """
        Handle received client list.
        """
        logging.debug("Handling client list")
        servers = data.get("servers")
        logging.debug(f"Received servers: {servers}")
        for server_info in servers:
            address = server_info.get("address")
            clients = server_info.get("clients")
            logging.debug(f"Server address: {address}, Clients: {clients}")
            for client_info in clients:
                client_public_key_pem = client_info["public_key"]
                username = client_info.get("username", "Unknown")
                fingerprint = compute_fingerprint(client_public_key_pem.encode("utf-8"))
                self.user_public_keys[fingerprint] = client_public_key_pem
                self.user_fingerprints[fingerprint] = username
                self.user_servers[fingerprint] = address
        print("\nUpdated client list.")
        print("Available clients:")
        for fingerprint, username in self.user_fingerprints.items():
            print(f"Username: {username}, Fingerprint: {fingerprint}")

    def upload_file(self, filename):
        """
        Upload a file to the server via HTTP API.
        """
        try:
            url = f'http://{self.server_ip}:8081/api/upload'
            files = {'file': open(filename, 'rb')}
            response = requests.post(url, files=files)
            if response.status_code == 200:
                data = response.json()
                file_url = data['file_url']
                print(f"File uploaded. Access it at: {file_url}")
                logging.debug(f"Uploaded file {filename}")
            else:
                print(f"Failed to upload file. Status code: {response.status_code}")
                logging.debug(f"Failed to upload file {filename}. Status code: {response.status_code}")
        except FileNotFoundError:
            print(f"File {filename} not found.")
            logging.debug(f"File {filename} not found.")

    def download_file(self, file_url):
        """
        Download a file from the server via HTTP API.
        """
        try:
            url = f"http://{self.server_ip}:8081{file_url}"
            response = requests.get(url)
            if response.status_code == 200:
                filename = file_url.split('/')[-1]
                directory = f"{self.username}_files"
                os.makedirs(directory, exist_ok=True)
                save_path = os.path.join(directory, filename)
                with open(save_path, 'wb') as f:
                    f.write(response.content)
                print(f"\nFile downloaded and saved as {save_path}")
                logging.debug(f"Downloaded file {filename}")
            else:
                print(f"Failed to download file. Status code: {response.status_code}")
                logging.debug(f"Failed to download file {file_url}. Status code: {response.status_code}")
        except Exception as e:
            print(f"Error downloading file: {e}")
            logging.error(f"Error downloading file {file_url}: {e}")

    def logout(self):
        """
        Logout from the server.
        """
        self.logged_in = False
        self.socket.close()
        print("Logged out.")

    def show_help(self):
        """
        Display help information for available commands.
        """
        help_text = """
Available commands:
    /list                     - Show online users.
    /msg <fingerprint> <message> - Send a private message to a user.
    /upload <filename>        - Upload a file to the server.
    /download <file_url>      - Download a file from the server.
    /help                     - Show this help message.
    quit                      - Exit the chat.
"""
        print(help_text)


if __name__ == "__main__":
    client = Client("127.0.0.1", 8080)
    client.start()
