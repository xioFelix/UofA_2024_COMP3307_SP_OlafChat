# client.py

import asyncio
import json
import logging
import os
import base64
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from websockets import connect
from aiohttp import ClientSession

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG for detailed logs
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Utility functions
def load_or_generate_user_keys(username):
    key_filename = f"{username}_private_key.pem"
    if os.path.exists(key_filename):
        with open(key_filename, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        logging.info(f"Loaded existing private key from {key_filename}.")
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        with open(key_filename, "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
        logging.info(f"Generated new private key and saved to {key_filename}.")
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return private_key, public_key_pem

def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(public_key, message, signature_b64):
    signature = base64.b64decode(signature_b64)
    try:
        public_key.verify(
            signature,
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        logging.warning(f"Signature verification failed: {e}")
        return False

def encrypt_message(message_json, recipient_public_key):
    try:
        # Generate AES key and IV
        aes_key = os.urandom(32)  # 256 bits
        iv = os.urandom(16)       # 128 bits

        # AES-GCM encryption
        encryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv),
        ).encryptor()
        ciphertext = encryptor.update(message_json.encode('utf-8')) + encryptor.finalize()
        tag = encryptor.tag  # Extract the authentication tag

        # Append the tag to the ciphertext
        encrypted_message = ciphertext + tag

        # Encrypt AES key with RSA-OAEP
        encrypted_key = recipient_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Prepare payload
        encrypted_payload = {
            "encrypted_key": base64.b64encode(encrypted_key).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8'),
            "encrypted_message": base64.b64encode(encrypted_message).decode('utf-8')
        }

        # Debugging
        logging.debug(f"Ciphertext length: {len(ciphertext)} bytes")
        logging.debug(f"Tag length: {len(tag)} bytes")
        logging.debug(f"Encrypted message length (ciphertext + tag): {len(encrypted_message)} bytes")

        return json.dumps(encrypted_payload)
    except Exception as e:
        logging.error(f"Encryption failed: {e}")
        raise

def decrypt_message(encrypted_payload_json, recipient_private_key):
    try:
        payload = json.loads(encrypted_payload_json)
        encrypted_key = base64.b64decode(payload['encrypted_key'])
        iv = base64.b64decode(payload['iv'])
        encrypted_message = base64.b64decode(payload['encrypted_message'])

        # Decrypt AES key with RSA-OAEP
        aes_key = recipient_private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Separate ciphertext and tag
        ciphertext = encrypted_message[:-16]  # Last 16 bytes are the tag
        tag = encrypted_message[-16:]

        # Debugging
        logging.debug(f"Ciphertext length: {len(ciphertext)} bytes")
        logging.debug(f"Tag length: {len(tag)} bytes")

        # AES-GCM decryption with tag
        decryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv, tag),
        ).decryptor()
        decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

        return decrypted_message.decode('utf-8')
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        raise

class Client:
    def __init__(self, server_ws_uri, server_http_uri):
        self.server_ws_uri = server_ws_uri
        self.server_http_uri = server_http_uri
        self.private_key = None
        self.public_key_pem = None
        self.username = None
        self.counter = 0
        self.server_public_key = None  # To be fetched from server
        self.received_user_public_keys = {}  # username -> public_key

    async def start(self):
        await self.initialize_keys()
        async with connect(self.server_ws_uri) as websocket:
            self.websocket = websocket
            await self.receive_server_public_key()

            await self.login_or_register()

            # Start listener
            asyncio.create_task(self.listen())

            # Main loop for user input
            while True:
                try:
                    user_input = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
                    if not user_input:
                        break
                    user_input = user_input.strip()
                    if user_input == "":
                        continue
                    if user_input.lower() == "quit":
                        logging.info("Exiting client.")
                        break
                    elif user_input.startswith("/list"):
                        await self.list_users()
                    elif user_input.startswith("/broadcast "):
                        message = user_input[len("/broadcast "):]
                        await self.broadcast(message)
                    elif user_input.startswith("/msg "):
                        parts = user_input.split(" ", 2)
                        if len(parts) < 3:
                            print("Usage: /msg <username> <message>")
                            continue
                        recipient, message = parts[1], parts[2]
                        await self.private_message(recipient, message)
                    elif user_input.startswith("/upload "):
                        parts = user_input.split(" ", 1)
                        if len(parts) < 2:
                            print("Usage: /upload <filepath>")
                            continue
                        filepath = parts[1]
                        await self.upload_file(filepath)
                    elif user_input.startswith("/download "):
                        parts = user_input.split(" ", 1)
                        if len(parts) < 2:
                            print("Usage: /download <file_url>")
                            continue
                        file_url = parts[1]
                        await self.download_file(file_url)
                    elif user_input.startswith("/get_public_key "):
                        parts = user_input.split(" ", 1)
                        if len(parts) < 2:
                            print("Usage: /get_public_key <username>")
                            continue
                        target_username = parts[1]
                        await self.get_public_key(target_username)
                    elif user_input.startswith("/help"):
                        self.show_help()
                    else:
                        print("Unknown command. Type /help for a list of commands.")
                except Exception as e:
                    logging.error(f"Error processing input: {e}")

    async def initialize_keys(self):
        self.username = input("Enter your username: ").strip()
        self.private_key, self.public_key_pem = load_or_generate_user_keys(self.username)
        logging.debug(f"Initialized keys for user {self.username}.")

    async def receive_server_public_key(self):
        server_pub_key_pem = await self.websocket.recv()
        self.server_public_key = serialization.load_pem_public_key(server_pub_key_pem.encode('utf-8'))
        logging.debug("Received server's public key.")

    async def login_or_register(self):
        choice = input("Do you want to (r)egister or (l)ogin? ").strip().lower()
        if choice == 'r':
            await self.register()
        elif choice == 'l':
            await self.login()
        else:
            print("Invalid choice. Exiting.")
            sys.exit(1)

    async def register(self):
        data = {
            "type": "hello",
            "username": self.username,
            "public_key": self.public_key_pem
        }
        signed_data = self.create_signed_data(data)
        await self.send_signed_message(signed_data)

    async def login(self):
        data = {
            "type": "login",
            "username": self.username,
            "public_key": self.public_key_pem
        }
        signed_data = self.create_signed_data(data)
        await self.send_signed_message(signed_data)

    def create_signed_data(self, data):
        self.counter += 1
        # Serialize 'data' to JSON and concatenate with 'counter' as string
        message = json.dumps(data) + str(self.counter)
        signature = sign_message(self.private_key, message)
        signed_data = {
            "type": "signed_data",
            "data": data,
            "counter": self.counter,
            "signature": signature
        }
        return signed_data

    async def send_signed_message(self, signed_data):
        try:
            message_json = json.dumps(signed_data)
            encrypted_payload = encrypt_message(message_json, self.server_public_key)
            await self.websocket.send(encrypted_payload)
            logging.debug(f"Sent signed message: {signed_data}")
        except Exception as e:
            logging.error(f"Failed to send signed message: {e}")

    async def listen(self):
        async for message in self.websocket:
            try:
                decrypted_json = decrypt_message(message, self.private_key)
                response = json.loads(decrypted_json)
                await self.process_response(response)
            except Exception as e:
                logging.error(f"Error processing incoming message: {e}")

    async def process_response(self, response):
        msg_type = response.get("type")
        if msg_type == "status":
            status = response.get("status")
            message = response.get("message")
            print(f"{status.upper()}: {message}")
            logging.debug(f"Received status: {status}, message: {message}")
        elif msg_type == "client_list":
            users = response.get("servers")
            print(f"Online users: {users}")
            logging.debug(f"Received client list: {users}")
        elif msg_type == "broadcast":
            sender = response.get("from")
            message = response.get("message")
            print(f"[Broadcast] {sender}: {message}")
            logging.debug(f"Received broadcast from {sender}: {message}")
        elif msg_type == "private_message":
            sender = response.get("from")
            encrypted_payload = response.get("message")
            counter = response.get("counter")
            message = await self.decrypt_private_message(sender, encrypted_payload, counter)
            if message:
                print(f"[Private] {sender}: {message}")
        elif msg_type == "public_key":
            target_username = response.get("username")
            public_key_pem = response.get("public_key")
            if target_username and public_key_pem:
                try:
                    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
                    self.received_user_public_keys[target_username] = public_key
                    print(f"Received public key for {target_username}.")
                    logging.debug(f"Received public key for {target_username}.")
                except Exception as e:
                    logging.error(f"Failed to load public key for {target_username}: {e}")
            else:
                logging.warning(f"Received malformed public key response: {response}")
        else:
            logging.warning(f"Unhandled message type: {msg_type}")

    async def list_users(self):
        data = {
            "type": "list_users"
        }
        signed_data = self.create_signed_data(data)
        await self.send_signed_message(signed_data)
        logging.debug("Requested user list.")

    async def broadcast(self, message):
        data = {
            "type": "broadcast",
            "body": message
        }
        signed_data = self.create_signed_data(data)
        await self.send_signed_message(signed_data)
        logging.debug(f"Broadcasted message: {message}")

    async def private_message(self, recipient, message):
        # Retrieve recipient's public key from received_user_public_keys
        recipient_public_key = self.received_user_public_keys.get(recipient)
        if not recipient_public_key:
            print(f"Public key for user '{recipient}' not found. Use /get_public_key {recipient} to retrieve it.")
            logging.warning(f"Public key for user '{recipient}' not found.")
            return

        try:
            # Encrypt the message payload
            aes_key = os.urandom(32)  # 256 bits
            iv = os.urandom(16)       # 128 bits

            # AES-GCM encryption
            encryptor = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(iv),
            ).encryptor()
            ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
            tag = encryptor.tag

            # Append the tag to the ciphertext
            encrypted_message = ciphertext + tag

            # Encrypt AES key with recipient's RSA-OAEP
            encrypted_key = recipient_public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            encrypted_payload = {
                "encrypted_key": base64.b64encode(encrypted_key).decode('utf-8'),
                "iv": base64.b64encode(iv).decode('utf-8'),
                "encrypted_message": base64.b64encode(encrypted_message).decode('utf-8')
            }

            # Create the private_message data structure
            data = {
                "type": "private_message",
                "to": recipient,
                "message": encrypted_payload,
                "counter": self.counter + 1  # Increment counter
            }
            signed_data = self.create_signed_data(data)
            await self.send_signed_message(signed_data)
            logging.debug(f"Sent private message to {recipient}.")
        except Exception as e:
            logging.error(f"Failed to send private message to {recipient}: {e}")

    async def decrypt_private_message(self, sender, encrypted_payload, counter):
        # Decrypt AES key with client's private RSA key
        encrypted_key = base64.b64decode(encrypted_payload['encrypted_key'])
        iv = base64.b64decode(encrypted_payload['iv'])
        encrypted_message = base64.b64decode(encrypted_payload['encrypted_message'])

        try:
            aes_key = self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            logging.error(f"Failed to decrypt AES key from {sender}: {e}")
            return None

        # Separate ciphertext and tag
        ciphertext = encrypted_message[:-16]  # Last 16 bytes are the tag
        tag = encrypted_message[-16:]

        # Debugging
        logging.debug(f"Ciphertext length: {len(ciphertext)} bytes")
        logging.debug(f"Tag length: {len(tag)} bytes")

        # AES-GCM decryption with tag
        try:
            decryptor = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(iv, tag),
            ).decryptor()
            decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
            return decrypted_message.decode('utf-8')
        except Exception as e:
            logging.error(f"Failed to decrypt message from {sender}: {e}")
            return None

    async def upload_file(self, filepath):
        if not os.path.exists(filepath):
            print(f"File {filepath} does not exist.")
            return

        filename = os.path.basename(filepath)
        url = f"{self.server_http_uri}/api/upload"

        async with ClientSession() as session:
            with open(filepath, 'rb') as f:
                data = {'file': f}
                try:
                    async with session.post(url, data={'file': f}) as resp:
                        if resp.status == 200:
                            result = await resp.json()
                            file_url = result.get("file_url")
                            print(f"File uploaded successfully: {file_url}")
                            logging.debug(f"Uploaded file {filename}: {file_url}")
                        else:
                            error = await resp.text()
                            print(f"Failed to upload file: {error}")
                            logging.error(f"Failed to upload file {filename}: {error}")
                except Exception as e:
                    logging.error(f"Exception during file upload: {e}")
                    print(f"Exception during file upload: {e}")

    async def download_file(self, file_url):
        async with ClientSession() as session:
            try:
                async with session.get(file_url) as resp:
                    if resp.status == 200:
                        filename = os.path.basename(file_url)
                        directory = f"{self.username}_downloads"
                        os.makedirs(directory, exist_ok=True)
                        file_path = os.path.join(directory, filename)
                        with open(file_path, 'wb') as f:
                            while True:
                                chunk = await resp.content.read(1024)
                                if not chunk:
                                    break
                                f.write(chunk)
                        print(f"File downloaded successfully: {file_path}")
                        logging.debug(f"Downloaded file from {file_url} to {file_path}")
                    else:
                        error = await resp.text()
                        print(f"Failed to download file: {error}")
                        logging.error(f"Failed to download file from {file_url}: {error}")
            except Exception as e:
                logging.error(f"Exception during file download: {e}")
                print(f"Exception during file download: {e}")

    async def get_public_key(self, target_username):
        # Request server to send public key of target_username
        data = {
            "type": "get_public_key",
            "username": target_username
        }
        signed_data = self.create_signed_data(data)
        await self.send_signed_message(signed_data)
        logging.debug(f"Requested public key for {target_username}.")

    def show_help(self):
        help_text = """
Available commands:
    /list                         - Show online users.
    /broadcast <message>          - Send a broadcast message.
    /msg <username> <message>     - Send a private message to a user.
    /upload <filepath>            - Upload a file to the server.
    /download <file_url>          - Download a file from the server.
    /get_public_key <username>    - Retrieve the public key of a user.
    /help                         - Show this help message.
    quit                          - Exit the chat.
        """
        print(help_text)
        logging.debug("Displayed help information.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python client.py <server_ws_uri> <server_http_uri>")
        print("Example: python client.py ws://localhost:8080 http://localhost:8000")
        sys.exit(1)

    server_ws_uri = sys.argv[1]
    server_http_uri = sys.argv[2]

    client = Client(server_ws_uri, server_http_uri)
    asyncio.run(client.start())
