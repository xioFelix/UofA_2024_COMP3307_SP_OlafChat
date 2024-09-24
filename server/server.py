import socket
import threading
import logging
import json
import os
import base64
from shared.encryption import (
    load_or_generate_private_key,
    load_public_key,
    serialize_public_key,
    encrypt_message,
    decrypt_message,
    verify_signature,
    sign_message,
)
from auth import UserManager

logging.basicConfig(level=logging.INFO)

# Global user manager
user_manager = UserManager("user_data.json")

# Global online users set and client connections dictionary
online_users = set()
client_connections = {}
client_handlers = {}  # Store ClientHandler instances

# Global file permissions dictionary
file_permissions = {}  # Stores {filename: {'owner': username, 'recipient': recipient}}


class ClientHandler(threading.Thread):
    """
    Handles communication with a connected client.
    """

    # Class-level dictionary to store counters for each client
    server_counters = {}
    
    # Class-level lock for thread-safe access to server_counters
    counters_lock = threading.Lock()

    def __init__(self, client_socket, address, server_private_key):
        threading.Thread.__init__(self)
        self.client_socket = client_socket
        self.address = address
        self.server_private_key = server_private_key
        self.client_public_key = None
        self.username = None
        self.logged_in = False
        self.lock = threading.Lock()
        self.counter = 0  # Counter for messages sent to the client

    def recvall(self, n):
        """
        Helper function to receive n bytes or return None if EOF is hit.
        """
        data = bytearray()
        while len(data) < n:
            packet = self.client_socket.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return data

    def run(self):
        try:
            logging.info(f"Handling client {self.address}")

            # Send server's public key
            server_public_key_pem = serialize_public_key(
                self.server_private_key.public_key()
            )
            self.client_socket.sendall(server_public_key_pem)

            # Receive message length first
            raw_msglen = self.recvall(4)
            if not raw_msglen:
                logging.warning("Client disconnected before sending data.")
                return
            message_length = int.from_bytes(raw_msglen, byteorder="big")

            # Now read the message data
            data = self.recvall(message_length)
            if not data:
                logging.warning("Client disconnected while sending data.")
                return

            # Decode the data as UTF-8
            message_json = data.decode('utf-8')
            message = json.loads(message_json)
        # Handle the message
            if message["type"] == "register":
                self.username = message["username"]
                client_public_key_pem = message["public_key"].encode("utf-8")
                self.client_public_key = load_public_key(client_public_key_pem)

                # Register user
                if user_manager.register_user(
                    self.username, client_public_key_pem.decode("utf-8")
                ):
                    self.logged_in = True
                    response_data = {
                        "status": "success",
                        "message": "Registered successfully.",
                    }
                else:
                    response_data = {
                        "status": "error",
                        "message": "Username already exists.",
                    }
                    self.send_response(response_data)
                    self.client_socket.close()
                    return

                self.send_response(response_data)

            elif message["type"] == "login":
                self.username = message["username"]
                client_public_key_pem = message["public_key"].encode("utf-8")
                self.client_public_key = load_public_key(client_public_key_pem)

                # Validate user
                stored_public_key_pem = user_manager.get_user_public_key(self.username)
                if (
                    stored_public_key_pem
                    and stored_public_key_pem == client_public_key_pem.decode("utf-8")
                ):
                    self.logged_in = True
                    response_data = {
                        "status": "success",
                        "message": "Logged in successfully.",
                    }
                else:
                    response_data = {
                        "status": "error",
                        "message": "Invalid username or key.",
                    }
                    self.send_response(response_data)
                    self.client_socket.close()
                    return

                self.send_response(response_data)

            else:
                response_data = {"status": "error", "message": "Invalid message type."}
                self.send_response(response_data)
                self.client_socket.close()
                return

            if self.logged_in:
                # User successfully logged in, add to online users and connections
                online_users.add(self.username)
                client_connections[self.username] = self.client_socket
                client_handlers[self.username] = self
                logging.info(
                    f"User {self.username} logged in. Online users: {online_users}"
                )

                # Initialize the last counter for this client
                with ClientHandler.counters_lock:
                    ClientHandler.server_counters[self.username] = 0

            # Main loop to handle client messages
            while self.logged_in:
                # Read the message length first
                raw_msglen = self.recvall(4)
                if not raw_msglen:
                    break
                message_length = int.from_bytes(raw_msglen, byteorder="big")
                # Now read the message data
                encrypted_message = self.recvall(message_length)
                if not encrypted_message:
                    break

                message_json = decrypt_message(
                    encrypted_message.decode("utf-8"), self.server_private_key
                )
                # Debugging: Log the decrypted message
                logging.debug(f"Decrypted message JSON: {message_json}")
                try:
                    message = json.loads(message_json)
                    logging.debug(f"Parsed message: {message}")
                except json.JSONDecodeError as e:
                    logging.error(f"JSON decoding failed: {e}")
                    continue  # Skip processing this message

                # Verify the message structure
                if message.get("type") == "signed_data":
                    data = message.get("data")
                    counter = message.get("counter")
                    signature = message.get("signature")

                    # Concatenate data and counter for signature verification
                    data_json = json.dumps(data)
                    to_verify = data_json + str(counter)

                    # Verify the signature
                    if not verify_signature(self.client_public_key, to_verify, signature):
                        logging.warning("Signature verification failed.")
                        continue  # Discard the message

                    # Check the counter to prevent replay attacks
                    with ClientHandler.counters_lock:
                        last_counter = ClientHandler.server_counters.get(self.username, 0)
                        if counter <= last_counter:
                            logging.warning("Replay attack detected or counter not increasing.")
                            continue  # Discard the message

                        # Update the counter
                        ClientHandler.server_counters[self.username] = counter

                    # Process the data
                    msg_type = data.get("type")
                    if msg_type == "list_users":
                        self.handle_list_users()
                    elif msg_type == "broadcast":
                        self.handle_broadcast(data.get("body"))
                    elif msg_type == "private_message":
                        self.handle_private_message(data)
                    elif msg_type == "get_public_key":
                        self.handle_get_public_key(data)
                    elif msg_type == "shared_key":
                        self.handle_shared_key(data)
                    elif msg_type == "upload":
                        self.handle_file_upload(data)
                    elif msg_type == "download":
                        self.handle_file_download(data)
                    elif msg_type == "file_list":
                        self.handle_file_list()
                    else:
                        self.handle_message(data)
                else:
                    logging.warning("Invalid message type received from client.")

        except Exception as e:
            logging.error(f"Error handling client {self.address}: {e}")
        finally:
            # Remove user from online users upon disconnection
            if self.username in online_users:
                online_users.remove(self.username)
                client_connections.pop(self.username, None)
                client_handlers.pop(self.username, None)
                with ClientHandler.counters_lock:
                    ClientHandler.server_counters.pop(self.username, None)  # Remove counter tracking
                logging.info(
                    f"User {self.username} disconnected. Online users: {online_users}"
                )
            self.client_socket.close()
            logging.info(f"Connection with {self.address} closed.")

    def send_response(self, data):
        """
        Send a response to the client with signature and encryption.
        """
        # Increment the counter
        self.counter += 1

        # Serialize the data
        data_json = json.dumps(data)

        # Concatenate data and counter for signing
        to_sign = data_json + str(self.counter)

        # Sign the concatenated string
        signature = sign_message(self.server_private_key, to_sign)

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
        encrypted_message = encrypt_message(message_json, self.client_public_key)
        encrypted_message_bytes = encrypted_message.encode("utf-8")
        message_length = len(encrypted_message_bytes)
        with self.lock:
            self.client_socket.sendall(message_length.to_bytes(4, byteorder="big"))
            self.client_socket.sendall(encrypted_message_bytes)


    def handle_list_users(self):
        """
        Handle a request for the list of online users.
        """
        user_list = list(online_users)
        response_data = {"type": "user_list", "users": user_list}
        self.send_response(response_data)

    def handle_broadcast(self, message_body):
        """
        Handle broadcasting a message to all online users.
        """
        # Construct the broadcast message
        broadcast_message = {
            "type": "broadcast",
            "from": self.username,
            "message": message_body,
        }

        # Send the message to all connected clients except the sender
        for username, handler in client_handlers.items():
            if username != self.username:
                try:
                    handler.send_raw_message(broadcast_message)  # Pass dict directly
                except Exception as e:
                    logging.error(f"Error sending broadcast to {username}: {e}")

    def handle_private_message(self, content_data):
        """
        Handle forwarding a private message to a specific user.
        """
        recipient = content_data.get("to")
        encrypted_message = content_data.get("message")
        counter = content_data.get("counter")  # Counter for replay attack prevention

        if recipient in client_handlers:
            try:
                # Forward the message to the recipient
                private_message = {
                    "type": "private_message",
                    "from": self.username,
                    "message": encrypted_message,
                    "counter": counter
                }
                # Pass dict directly without JSON serialization
                recipient_handler = client_handlers[recipient]
                recipient_handler.send_raw_message(private_message)
                logging.info(
                    f"Forwarded private message from {self.username} to {recipient}"
                )
            except Exception as e:
                logging.error(f"Error forwarding private message to {recipient}: {e}")
        else:
            # Recipient is not online
            response = {
                "status": "error",
                "message": f"User {recipient} is not online.",
            }
            self.send_response(response)

    def handle_get_public_key(self, content_data):
        """
        Handle a request to get another user's public key.
        """
        target_user = content_data.get("username")
        public_key_pem = user_manager.get_user_public_key(target_user)
        if public_key_pem:
            response = {
                "type": "public_key",
                "username": target_user,
                "public_key": public_key_pem,
            }
        else:
            response = {"status": "error", "message": f"User {target_user} not found."}
        self.send_response(response)

    def handle_shared_key(self, content_data):
        """
        Handle forwarding an encrypted shared key to another user.
        """
        recipient = content_data.get("to")
        encrypted_shared_key = content_data.get("encrypted_shared_key")

        if recipient in client_handlers:
            try:
                # Forward the encrypted shared key to the recipient
                shared_key_message = {
                    "type": "shared_key",
                    "from": self.username,
                    "encrypted_shared_key": encrypted_shared_key,
                }
                recipient_handler = client_handlers[recipient]
                recipient_handler.send_raw_message(shared_key_message)
                logging.info(
                    f"Forwarded shared key from {self.username} to {recipient}"
                )
            except Exception as e:
                logging.error(f"Error forwarding shared key to {recipient}: {e}")
        else:
            # Recipient is not online
            response = {
                "status": "error",
                "message": f"User {recipient} is not online.",
            }
            self.send_response(response)

    def handle_file_upload(self, content_data):
        """
        Handle file upload from a client.
        """
        filename = content_data.get("filename")
        file_data_b64 = content_data.get("file_data")
        recipient = content_data.get("recipient")  # None means public
        file_data = base64.b64decode(file_data_b64)

        # Save the file to server_files directory
        save_path = os.path.join("server_files", filename)
        os.makedirs("server_files", exist_ok=True)
        with open(save_path, "wb") as f:
            f.write(file_data)
        logging.info(
            f"File {filename} uploaded by {self.username} and saved to {save_path}"
        )

        # Store file permissions
        file_permissions[filename] = {
            "owner": self.username,
            "recipient": recipient,  # None means public
        }

        response = {
            "status": "success",
            "message": f"File {filename} uploaded successfully.",
        }
        self.send_response(response)

        # Notify recipient if file is private
        if recipient:
            if recipient in client_handlers:
                try:
                    notification = {
                        "type": "notification",
                        "message": f"{self.username} has uploaded a file '{filename}' for you.",
                    }
                    recipient_handler = client_handlers[recipient]
                    recipient_handler.send_raw_message(notification)
                    logging.info(
                        f"Sent file upload notification to {recipient} for file '{filename}'"
                    )
                except Exception as e:
                    logging.error(f"Error sending notification to {recipient}: {e}")
        else:
            # Notify all users about the new public file
            notification = {
                "type": "notification",
                "message": f"{self.username} has uploaded a new public file '{filename}'.",
            }
            for username, handler in client_handlers.items():
                if username != self.username:
                    try:
                        handler.send_raw_message(notification)
                        logging.info(
                            f"Sent public file upload notification to {username} for file '{filename}'"
                        )
                    except Exception as e:
                        logging.error(f"Error sending notification to {username}: {e}")

    def handle_file_download(self, content_data):
        """
        Handle file download request from a client.
        """
        filename = content_data.get("filename")
        file_path = os.path.join("server_files", filename)
        if os.path.exists(file_path):
            # Check file permissions
            permissions = file_permissions.get(filename)
            if permissions:
                recipient = permissions.get("recipient")
                if (
                    recipient
                    and recipient != self.username
                    and permissions.get("owner") != self.username
                ):
                    response = {
                        "status": "error",
                        "message": f"You do not have permission to download {filename}.",
                    }
                    self.send_response(response)
                    return
            else:
                response = {
                    "status": "error",
                    "message": f"File permissions not found for {filename}.",
                }
                self.send_response(response)
                return

            with open(file_path, "rb") as f:
                file_data = f.read()
            file_data_b64 = base64.b64encode(file_data).decode("utf-8")
            response = {
                "type": "file_data",
                "filename": filename,
                "file_data": file_data_b64,
            }
            self.send_response(response)
            logging.info(f"Sent file {filename} to {self.username}")
        else:
            response = {
                "status": "error",
                "message": f"File {filename} not found on server.",
            }
            self.send_response(response)

    def handle_file_list(self):
        """
        Handle a request to get the list of downloadable files for the user.
        """
        user_files = []
        for filename, permissions in file_permissions.items():
            # File is public, or user is the recipient or owner
            if (
                permissions["recipient"] is None
                or permissions["recipient"] == self.username
                or permissions["owner"] == self.username
            ):
                user_files.append(filename)
        response = {"type": "file_list", "files": user_files}
        self.send_response(response)

    def handle_message(self, content_data):
        """
        Handle other types of messages.
        """
        logging.info(f"Received message from {self.username}: {content_data}")
        response = {"status": "success", "message": "Message received."}
        self.send_response(response)

    def send_raw_message(self, data):
        """
        Send a message to the client with signature and encryption.
        """
        # Increment the counter
        self.counter += 1

        # Serialize the data
        data_json = json.dumps(data)

        # Concatenate data and counter for signing
        to_sign = data_json + str(self.counter)

        # Sign the concatenated string
        signature = sign_message(self.server_private_key, to_sign)

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
        encrypted_message = encrypt_message(message_json, self.client_public_key)
        encrypted_message_bytes = encrypted_message.encode("utf-8")
        message_length = len(encrypted_message_bytes)
        with self.lock:
            self.client_socket.sendall(message_length.to_bytes(4, byteorder="big"))
            self.client_socket.sendall(encrypted_message_bytes)


def start_server(host="0.0.0.0", port=8080):
    """
    Start the chat server.
    """
    server_private_key = load_or_generate_private_key("server_private_key.pem")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    logging.info(f"Server started and listening on {host}:{port}")

    try:
        while True:
            client_socket, address = server_socket.accept()
            handler = ClientHandler(client_socket, address, server_private_key)
            handler.start()
    except KeyboardInterrupt:
        logging.info("Server shutting down.")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_server()
