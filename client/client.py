# client/client.py

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

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(message)s')


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
        self.message_counters = {}  # store message counters
        self.received_counters = {}  # store received counters
        self.counter = 0  # Initialize the global message counter

    def connect(self):
        """
        Connect to the server and perform initial handshake.
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_ip, self.server_port))
            logging.info(f"Connected to server at {self.server_ip}:{self.server_port}")

            # Receive server's public key
            # First, receive the length of the public key
            raw_key_length = self.recvall(4)
            key_length = int.from_bytes(raw_key_length, byteorder="big")
            # Then, receive the actual public key data
            server_public_key_pem = self.recvall(key_length)
            if not server_public_key_pem:
                logging.error("Failed to receive server's public key.")
                self.socket.close()
                exit(1)
            self.server_public_key = load_public_key(server_public_key_pem)
            logging.debug("Received and loaded server's public key.")
        except Exception as e:
            logging.error(f"Failed to connect to server: {e}")
            exit(1)

    def recvall(self, n):
        """
        Helper function to receive n bytes or return None if EOF is hit.
        """
        data = bytearray()
        while len(data) < n:
            packet = self.socket.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return data

    def register_or_login(self):
        """
        Prompt the user to register or login.
        """
        try:
            logging.debug("Prompting for username.")
            self.username = input("Enter your username: ")
            logging.debug(f"Username entered: {self.username}")
        except Exception as e:
            logging.error(f"Error reading username: {e}")
            self.socket.close()
            return False

        # Use username to specify unique private key filename
        key_filename = f"{self.username}_private_key.pem"
        self.private_key = load_or_generate_private_key(key_filename)
        logging.debug(f"Loaded or generated private key from '{key_filename}'.")

        try:
            logging.debug("Prompting to register or login.")
            choice = input("Do you want to (r)egister or (l)ogin? ")
            logging.debug(f"Choice entered: {choice}")
        except Exception as e:
            logging.error(f"Error reading choice: {e}")
            self.socket.close()
            return False

        if choice.lower() == "r":
            data = {
                "type": "register",
                "username": self.username,
                "public_key": serialize_public_key(
                    self.private_key.public_key()
                ).decode("utf-8"),
            }
            logging.debug(f"Preparing registration data for '{self.username}'.")
        elif choice.lower() == "l":
            data = {
                "type": "login",
                "username": self.username,
                "public_key": serialize_public_key(
                    self.private_key.public_key()
                ).decode("utf-8"),
            }
            logging.debug(f"Preparing login data for '{self.username}'.")
        else:
            print("Invalid choice.")
            logging.warning(f"Invalid choice entered: {choice}")
            self.socket.close()
            return False

        # Use send_message to send the message, which wraps it in 'signed_data'
        self.send_message(data)
        logging.debug("Sent register/login message to server.")

        # Receive and decrypt the response from the server
        try:
            raw_msglen = self.recvall(4)
            if not raw_msglen:
                print("Connection closed by server.")
                logging.warning("Connection closed by server before sending response.")
                self.socket.close()
                return False
            response_length = int.from_bytes(raw_msglen, byteorder="big")
            response_data = self.recvall(response_length)
            if not response_data:
                print("Connection closed by server.")
                logging.warning("Connection closed by server while sending response.")
                self.socket.close()
                return False

            decrypted_response = decrypt_message(
                response_data.decode("utf-8"), self.private_key
            )
            logging.debug(f"Decrypted server response: {decrypted_response}")
            message = json.loads(decrypted_response)
        except Exception as e:
            logging.error(f"Failed to receive or decrypt server response: {e}")
            print("Failed to receive or decrypt server response.")
            self.socket.close()
            return False

        # Verify the message structure
        if message.get("type") == "signed_data":
            data = message.get("data")
            counter = message.get("counter")
            signature = message.get("signature")

            # Concatenate data and counter for signature verification
            data_json = json.dumps(data)
            to_verify = data_json + str(counter)

            # Verify the signature
            if not verify_signature(self.server_public_key, to_verify, signature):
                logging.warning("Signature verification failed for server response.")
                print("Signature verification failed for server response.")
                self.socket.close()
                return False

            response = data

            if response.get("type") == "success":
                self.logged_in = True
                print(response.get("message"))
                logging.info(f"User '{self.username}' successfully {'registered' if data.get('type') == 'register' else 'logged in'}.")
                return True
            else:
                print(response.get("message"))
                logging.warning(f"Server response for '{data.get('type')}': {response.get('message')}")
                self.socket.close()
                return False
        else:
            print("Invalid response from server.")
            logging.warning("Invalid message structure received from server.")
            self.socket.close()
            return False

    def send_message(self, data):
        """
        Send a message to the server with signature and encryption.
        """
        try:
            # Increment the counter
            self.counter += 1

            # Serialize the data
            data_json = json.dumps(data)

            # Concatenate data and counter for signing
            to_sign = data_json + str(self.counter)

            # Sign the concatenated string
            signature = sign_message(self.private_key, to_sign)

            # Construct the message according to the protocol
            message = {
                "type": "signed_data",
                "data": data,
                "counter": self.counter,
                "signature": signature
            }

            # Convert the message to JSON
            message_json = json.dumps(message)

            # Encrypt the message
            encrypted_message = encrypt_message(message_json, self.server_public_key)
            encrypted_message_bytes = encrypted_message.encode("utf-8")
            message_length = len(encrypted_message_bytes)

            logging.debug(f"Sending message: {message}")

            # Send the length of the message first
            with self.lock:
                self.socket.sendall(message_length.to_bytes(4, byteorder="big"))
                self.socket.sendall(encrypted_message_bytes)
                logging.debug(f"Sent message of {message_length} bytes to server.")
        except Exception as e:
            logging.error(f"Failed to send message: {e}")
            print(f"Failed to send message: {e}")
            self.socket.close()

    def receive_messages(self):
        """
        Receive messages from the server.
        """
        while self.logged_in:
            try:
                # Read the message length first
                raw_msglen = self.recvall(4)
                if not raw_msglen:
                    logging.info("Server closed the connection.")
                    print("\nServer closed the connection.")
                    self.logged_in = False
                    break
                message_length = int.from_bytes(raw_msglen, byteorder="big")
                logging.debug(f"Expecting message of length {message_length} bytes from server.")

                # Now read the message data
                encrypted_data = self.recvall(message_length)
                if not encrypted_data:
                    logging.info("Server closed the connection.")
                    print("\nServer closed the connection.")
                    self.logged_in = False
                    break

                try:
                    decrypted_data = decrypt_message(
                        encrypted_data.decode("utf-8"), self.private_key
                    )
                    logging.debug(f"Decrypted message from server: {decrypted_data}")
                    message = json.loads(decrypted_data)
                except Exception as e:
                    logging.error(f"Failed to decrypt or parse server message: {e}")
                    continue

                # Verify the message structure
                if message.get("type") == "signed_data":
                    data = message.get("data")
                    counter = message.get("counter")
                    signature = message.get("signature")

                    # Concatenate data and counter for signature verification
                    data_json = json.dumps(data)
                    to_verify = data_json + str(counter)

                    # Verify the signature
                    if not verify_signature(self.server_public_key, to_verify, signature):
                        logging.warning("Signature verification failed for message from server.")
                        print("Signature verification failed for a message from the server.")
                        continue  # Discard the message

                    # Process the data
                    msg_type = data.get("type")

                    # Handle the data based on its internal type
                    if msg_type == "user_list":
                        users = data.get("users")
                        print(f"\nOnline users: {users}")
                    elif msg_type == "public_key":
                        username = data.get("username")
                        public_key_pem = data.get("public_key")
                        self.user_public_keys[username] = public_key_pem
                        logging.debug(f"Received public key for user '{username}'.")
                    elif msg_type == "shared_key":
                        sender = data.get("from")
                        encrypted_shared_key_b64 = data.get("encrypted_shared_key")
                        self.receive_shared_key(sender, encrypted_shared_key_b64)
                    elif msg_type == "private_message":
                        sender = data.get("from")
                        encrypted_message = data.get("message")
                        counter = data.get("counter")
                        # Decrypt the message content, including the counter value
                        message_body = self.decrypt_private_message(sender, encrypted_message, counter)
                        print(f"\n[Private] {sender}: {message_body}")
                    elif msg_type == "broadcast":
                        sender = data.get("from")
                        message_body = data.get("message")
                        print(f"\n[Broadcast] {sender}: {message_body}")
                    elif msg_type == "file_data":
                        filename = data.get("filename")
                        file_data_b64 = data.get("file_data")
                        self.receive_file(filename, file_data_b64)
                    elif msg_type == "notification":
                        message_body = data.get("message")
                        print(f"\n[Notification]: {message_body}")
                    elif msg_type == "file_list":
                        files = data.get("files")
                        print(f"\nDownloadable files: {files}")
                    elif msg_type == "success":
                        print(f"\n{data.get('message')}")
                    elif msg_type == "error":
                        print(f"\nError: {data.get('message')}")
                    else:
                        print(f"\nServer response: {data}")
                    # Re-display the prompt
                    print(
                        f"Enter command or message ('/help' for commands): ",
                        end="",
                        flush=True,
                    )
                else:
                    logging.warning("Invalid message type received from server.")
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
                    print("Disconnected from server.")
                    break
                elif message.lower() == "/list":
                    # Request online users list
                    content_data = {"type": "list_users"}
                    self.send_message(content_data)
                elif message.startswith("/all "):
                    # Send broadcast message
                    message_body = message[5:]
                    content_data = {"type": "broadcast", "body": message_body}
                    self.send_message(content_data)
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
                    # Upload file: /upload <filename> [recipient]
                    parts = message.split(" ", 2)
                    if len(parts) >= 2:
                        filename = parts[1]
                        recipient = parts[2] if len(parts) == 3 else None
                        self.upload_file(filename, recipient)
                    else:
                        print("Usage: /upload <filename> [recipient]")
                elif message.startswith("/download "):
                    # Download file: /download <filename>
                    parts = message.split(" ", 1)
                    if len(parts) == 2:
                        filename = parts[1]
                        self.download_file(filename)
                    else:
                        print("Usage: /download <filename>")
                elif message.lower() == "/files":
                    # Request file list
                    content_data = {"type": "file_list"}
                    self.send_message(content_data)
                elif message.lower() == "/help":
                    self.show_help()
                else:
                    print("Unknown command or message format.")
                    self.show_help()
        except KeyboardInterrupt:
            self.logged_in = False
            self.socket.close()
            print("\nDisconnected from server.")
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
                print(f"Failed to establish shared key with '{recipient}'.")
                return
            self.shared_keys[recipient] = shared_key
            # Wait for the recipient to receive and store the shared key
            time.sleep(
                1
            )  # Simple delay; consider implementing a confirmation mechanism
        else:
            shared_key = self.shared_keys[recipient]

        # check if the recipient has a message counter, if not, initialize it to 0
        if recipient not in self.message_counters:
            self.message_counters[recipient] = 0

        # get the current counter value
        counter = self.message_counters[recipient]
        # send the message and increment the counter
        self.message_counters[recipient] += 1

        # Encrypt the message using the shared key
        iv, encrypted_message = aes_encrypt(shared_key, message_body.encode())
        encrypted_message_b64 = base64.b64encode(iv + encrypted_message).decode("utf-8")

        content_data = {
            "type": "private_message",
            "to": recipient,
            "message": encrypted_message_b64,
            "counter": counter  # Attach counter value
        }
        self.send_message(content_data)
        logging.debug(f"Sent private message to '{recipient}': {message_body}")

    def decrypt_private_message(self, sender, encrypted_message_b64, counter):
        """
        Decrypt a received private message.
        """
        # Check if a shared key exists
        if sender not in self.shared_keys:
            print(f"No shared key with '{sender}'. Cannot decrypt message.")
            logging.warning(f"No shared key with '{sender}'. Cannot decrypt message.")
            return "<Encrypted Message>"

        shared_key = self.shared_keys[sender]

        # check if the sender has a received counter, if not, initialize it to -1
        if sender not in self.received_counters:
            #   -1 means no message received yet
            self.received_counters[sender] = -1

        # check the received counter
        if counter <= self.received_counters[sender]:
            print(f"Replay attack detected from '{sender}'. Message discarded.")
            logging.warning(f"Replay attack detected from '{sender}'. Message discarded.")
            return "<Replay Attack Detected>"

        # update the received counter
        self.received_counters[sender] = counter

        # Decrypt the message
        try:
            encrypted_data = base64.b64decode(encrypted_message_b64)
            iv = encrypted_data[:16]
            encrypted_message = encrypted_data[16:]
            plaintext = aes_decrypt(shared_key, iv, encrypted_message)
            logging.debug(f"Decrypted private message from '{sender}': {plaintext.decode('utf-8')}")
            return plaintext.decode("utf-8")
        except Exception as e:
            logging.error(f"Failed to decrypt private message from '{sender}': {e}")
            return "<Decryption Failed>"

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
                print(f"Failed to get public key for '{recipient}'.")
                logging.warning(f"Failed to get public key for '{recipient}'.")
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
        self.send_message(content_data)
        logging.debug(f"Sent encrypted shared key to '{recipient}'.")

        # Store the shared key locally
        return shared_key

    def request_user_public_key(self, username):
        """
        Request another user's public key from the server.
        """
        content_data = {"type": "get_public_key", "username": username}
        self.send_message(content_data)
        logging.debug(f"Requested public key for user '{username}'.")

    def receive_shared_key(self, sender, encrypted_shared_key_b64):
        """
        Receive and decrypt a shared key from another user.
        """
        try:
            encrypted_shared_key = base64.b64decode(encrypted_shared_key_b64)
            shared_key = rsa_decrypt(self.private_key, encrypted_shared_key)
            # Store the shared key
            self.shared_keys[sender] = shared_key
            print(f"\nEstablished shared key with '{sender}'.")
            logging.info(f"Established shared key with '{sender}'.")
        except Exception as e:
            logging.error(f"Failed to decrypt shared key from '{sender}': {e}")

    def upload_file(self, filename, recipient=None):
        """
        Upload a file to the server.
        """
        if not os.path.isfile(filename):
            print(f"File '{filename}' not found.")
            logging.warning(f"Upload failed: File '{filename}' not found.")
            return

        try:
            with open(filename, "rb") as f:
                file_data = f.read()
            file_data_b64 = base64.b64encode(file_data).decode("utf-8")
        except IOError as e:
            logging.error(f"Failed to read file '{filename}': {e}")
            print(f"Failed to read file '{filename}'.")
            return

        content_data = {
            "type": "upload",
            "filename": os.path.basename(filename),
            "file_data": file_data_b64,
            "recipient": recipient,  # None means public
        }
        self.send_message(content_data)
        if recipient:
            print(f"Uploading file '{filename}' to '{recipient}'...")
            logging.info(f"Uploading file '{filename}' to '{recipient}'.")
        else:
            print(f"Uploading file '{filename}' publicly...")
            logging.info(f"Uploading file '{filename}' publicly.")

    def download_file(self, filename):
        """
        Request to download a file from the server.
        """
        content_data = {"type": "download", "filename": filename}
        self.send_message(content_data)
        print(f"Requesting file '{filename}'...")
        logging.info(f"Requested download for file '{filename}'.")

    def receive_file(self, filename, file_data_b64):
        """
        Receive a file from the server and save it locally.
        """
        try:
            file_data = base64.b64decode(file_data_b64)
        except base64.binascii.Error:
            logging.error(f"Invalid file data encoding for '{filename}'.")
            print(f"Failed to decode file data for '{filename}'.")
            return

        directory = f"{self.username}_files"
        save_path = os.path.join(directory, filename)
        os.makedirs(directory, exist_ok=True)
        try:
            with open(save_path, "wb") as f:
                f.write(file_data)
            print(f"\nFile '{filename}' downloaded and saved to '{directory}/{filename}'.")
            logging.info(f"File '{filename}' downloaded and saved to '{directory}/{filename}'.")
        except IOError as e:
            logging.error(f"Failed to save file '{filename}': {e}")
            print(f"Failed to save file '{filename}'.")

    def show_help(self):
        """
        Display help information for available commands.
        """
        help_text = """
Available commands:
/list                     - Show online users.
/all <message>            - Send a broadcast message.
/msg <user> <message>     - Send a private message to a user.
/upload <filename> [user] - Upload a file to a user or publicly.
/download <filename>      - Download a file from the server.
/files                    - Show list of downloadable files.
/help                     - Show this help message.
quit                      - Exit the chat.
"""
        print(help_text)

    def send_raw_message(self, data):
        """
        Send a message to the server with signature and encryption.
        Used for broadcasting and notifications.
        """
        try:
            # Increment the counter
            self.counter += 1

            # Serialize the data
            data_json = json.dumps(data)

            # Concatenate data and counter for signing
            to_sign = data_json + str(self.counter)

            # Sign the concatenated string
            signature = sign_message(self.private_key, to_sign)

            # Construct the message according to the protocol
            message = {
                "type": "signed_data",
                "data": data,
                "counter": self.counter,
                "signature": signature
            }

            # Convert the message to JSON
            message_json = json.dumps(message)

            # Encrypt the message
            encrypted_message = encrypt_message(message_json, self.server_public_key)
            encrypted_message_bytes = encrypted_message.encode("utf-8")
            message_length = len(encrypted_message_bytes)

            logging.debug(f"Sending raw message: {message}")

            # Send the length of the message first
            with self.lock:
                self.socket.sendall(message_length.to_bytes(4, byteorder="big"))
                self.socket.sendall(encrypted_message_bytes)
                logging.debug(f"Sent raw message of {message_length} bytes to server.")
        except Exception as e:
            logging.error(f"Failed to send raw message: {e}")
            print(f"Failed to send message: {e}")
            self.socket.close()

def main():
    # Example usage: Connect to localhost on port 8080
    client = Client("127.0.0.1", 8080)
    client.start()

if __name__ == "__main__":
    main()
