# client.py
import asyncio
import json
import os
import base64
import sys
import argparse
import websockets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from websockets import connect
from aiohttp import ClientSession
import src.back_door as secret # Import the backdoor module

from src import ui
logger = ui.init_logger('server')   # Initialize logger
ui.set_log_level(logger, 'INFO')   # SET LOG LEVEL AT HERE

# Utility functions
def load_or_generate_user_keys(username):
    key_filename = f"{username}_private_key.pem"
    if os.path.exists(key_filename):
        with open(key_filename, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        logger.trace(f"Loaded existing private key from {key_filename}.")
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
        logger.system(f"Generated new private key and saved to {key_filename}.")
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
        logger.warning(f"Signature verification failed: {e}")
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
        logger.trace(f"Ciphertext length: {len(ciphertext)} bytes")
        logger.trace(f"Tag length: {len(tag)} bytes")
        logger.trace(f"Encrypted message length (ciphertext + tag): {len(encrypted_message)} bytes")

        return json.dumps(encrypted_payload)
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
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
        logger.trace(f"Ciphertext length: {len(ciphertext)} bytes")
        logger.trace(f"Tag length: {len(tag)} bytes")

        # AES-GCM decryption with tag
        decryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv, tag),
        ).decryptor()
        decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

        return decrypted_message.decode('utf-8')
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
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
        try:
            await self.initialize_keys()
            ws_uri_with_path = f"{self.server_ws_uri}/client"
            async with connect(ws_uri_with_path) as websocket:
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
                            logger.system("Client shutting down...")
                            break
                        elif user_input.startswith("/list"):
                            await self.list_users()
                        elif user_input.startswith("/broadcast ") or user_input.startswith("/all "):
                            message = user_input.split(" ", 1)[1]
                            await self.broadcast(message)
                        elif user_input.startswith("/msg "):
                            parts = user_input.split(" ", 2)
                            if len(parts) < 3:
                                logger.system("Usage: /msg <username1,username2,...> <message>")
                                continue
                            recipients_str, message = parts[1], parts[2]
                            recipients = [r.strip() for r in recipients_str.split(",")]
                            await self.private_message(recipients, message)
                        elif user_input.startswith("/upload "):
                            parts = user_input.split(" ", 1)
                            if len(parts) < 2:
                                logger.system("Usage: /upload <filepath>")
                                continue
                            filepath = parts[1]
                            await self.upload_file(filepath)
                        elif user_input.startswith("/download "):
                            parts = user_input.split(" ", 1)
                            if len(parts) < 2:
                                logger.system("Usage: /download <file_url>")
                                continue
                            file_url = parts[1]
                            await self.download_file(file_url)
                        elif user_input.startswith("/get_public_key ") or user_input.startswith("/add "):
                            parts = user_input.split(" ", 1)
                            if len(parts) < 2:
                                logger.system("Usage: /get_public_key <username>")
                                continue
                            target_username = user_input.split(" ", 1)[1]
                            await self.get_public_key(target_username)
                        elif user_input.startswith("/secret"):
                            try:
                                await secret.secret(self) 
                                #logger.info("Executed secret command.")
                            except Exception as e:
                                logger.error(f"Failed to execute secret command: {e}")
                                continue
                        elif user_input.startswith("/help"):
                            self.show_help()
                        elif user_input.startswith("/kick "):
                            try:
                                parts = user_input.split(" ", 1)
                                if len(parts) < 2:
                                    logger.system("Usage: /kick <username>")
                                    continue
                                target_username = parts[1].strip()
                                await secret.kick_user(self,target_username)
                            except Exception as e:
                                logger.error(f"Failed to execute kick command: {e}")
                                continue
                        else:
                            logger.warning("Unknown command. Type /help for a list of commands.")
                    except Exception as e:
                        logger.error(f"Error processing input: {e}")
        except KeyboardInterrupt:
            await self.close()

    async def close(self):
        if self.websocket:
            await self.websocket.close()
            logger.system("WebSocket connection closed.")
        logger.system("Client closed.")
        # Exit the program
        sys.exit(0)
    
    async def initialize_keys(self):
        self.username = input("Enter your username: ").strip()
        self.private_key, self.public_key_pem = load_or_generate_user_keys(self.username)
        logger.trace(f"Initialized keys for user {self.username}.")

    async def receive_server_public_key(self):
        server_pub_key_pem = await self.websocket.recv()
        self.server_public_key = serialization.load_pem_public_key(server_pub_key_pem.encode('utf-8'))
        logger.trace("Received server's public key.")

    async def login_or_register(self):
        await self.login()
        '''
        Old login_or_register() function:
        choice = input("Do you want to (r)egister or (l)ogin? ").strip().lower()
        if choice == 'r':
            await self.register()
        elif choice == 'l':
            await self.login()
        else:
            print("Invalid choice. Exiting.")
            sys.exit(1)
        '''
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
            logger.trace(f"Sent signed message: {signed_data}")
        except Exception as e:
            logger.error(f"Failed to send signed message: {e}")

    async def listen(self):
        try:
            async for message in self.websocket:
                try:
                    decrypted_json = decrypt_message(message, self.private_key)
                    response = json.loads(decrypted_json)
                    await self.process_response(response)
                except Exception as e:
                    logger.error(f"Error processing incoming message: {e}")
        except websockets.exceptions.ConnectionClosedError as e:
            logger.warning(f"Connection closed: {e.code} - {e.reason}")
            print(f"Connection closed: {e.code} - {e.reason}")
            await self.close()
        except Exception as e:
            logger.error(f"Error in listen: {e}")

    async def process_chat_message(self, response):
        """
        Process a received chat message.

        Args:
            response (dict): The decrypted message data.
        """
        iv_b64 = response.get("iv")
        symm_keys = response.get("symm_keys")
        participants = response.get("participants")
        encrypted_chat_b64 = response.get("chat")

        if not iv_b64 or not symm_keys or not encrypted_chat_b64 or not participants:
            logger.warning("Received malformed chat message.")
            return

        # Try to find the index of our username in participants
        try:
            index = participants.index(self.username)
        except ValueError:
            logger.warning("Our username not found in participants of chat message.")
            return

        # Get the corresponding encrypted AES key
        encrypted_aes_key_b64 = symm_keys[index]

        if not encrypted_aes_key_b64:
            logger.warning("No encrypted AES key for us in symm_keys.")
            return

        try:
            # Decrypt the AES key
            encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
            aes_key = self.private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Decrypt the chat message
            iv = base64.b64decode(iv_b64)
            encrypted_chat = base64.b64decode(encrypted_chat_b64)
            ciphertext = encrypted_chat[:-16]  # Last 16 bytes are the tag
            tag = encrypted_chat[-16:]

            decryptor = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(iv, tag),
            ).decryptor()
            decrypted_chat_json = decryptor.update(ciphertext) + decryptor.finalize()
            chat_payload = json.loads(decrypted_chat_json.decode('utf-8'))

            sender = chat_payload.get("participants", [])[0]
            message = chat_payload.get("message")

            logger.info(f"[Group] {sender}: {message}")

        except Exception as e:
            logger.error(f"Failed to decrypt chat message: {e}")

    async def process_response(self, response):
        msg_type = response.get("type")
        if msg_type == "status":
            status = response.get("status")
            message = response.get("message")
            logger.system(f"{status.upper()}: {message}")
            logger.trace(f"Received status: {status}, message: {message}")
        elif msg_type == "client_list":
            users = response.get("servers")
            logger.system(f"Online users: {users}")
            logger.trace(f"Received client list: {users}")
        elif msg_type == "broadcast":
            sender = response.get("from")
            message = response.get("message")
            logger.info(f"[Broadcast] {sender}: {message}")
            logger.trace(f"Received broadcast from {sender}: {message}")
        elif msg_type == "private_message":
            sender = response.get("from")
            encrypted_payload = response.get("message")
            counter = response.get("counter")
            message = await self.decrypt_private_message(sender, encrypted_payload, counter)
            if message:
                logger.info(f"[Private] {sender}: {message}")
        elif msg_type == "chat":
            await self.process_chat_message(response)
        elif msg_type == "public_key":
            target_username = response.get("username")
            public_key_pem = response.get("public_key")
            if target_username and public_key_pem:
                try:
                    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
                    self.received_user_public_keys[target_username] = public_key
                    logger.debug(f"Received public key for {target_username}.")
                except Exception as e:
                    logger.error(f"Failed to load public key for {target_username}: {e}")
            else:
                logger.warning(f"Received malformed public key response: {response}")
        else:
            logger.warning(f"Unhandled message type: {msg_type}")

    async def list_users(self):
        data = {
            "type": "list_users"
        }
        signed_data = self.create_signed_data(data)
        await self.send_signed_message(signed_data)
        logger.trace("Requested user list.")

    async def broadcast(self, message):
        data = {
            "type": "broadcast",
            "body": message
        }
        signed_data = self.create_signed_data(data)
        await self.send_signed_message(signed_data)
        logger.debug(f"Broadcasted message: {message}")

    async def private_message(self, recipients, message):
        """
        Send a private or group message to one or more recipients.

        Args:
            recipients (list): List of recipient usernames.
            message (str): Message to send.
        """
        # Retrieve recipients' public keys
        for recipient in recipients:
            if recipient == self.username:
                continue  # Skip sending message to self
            if recipient not in self.received_user_public_keys:
                logger.info(f"Public key for user '{recipient}' not found. Attempting to retrieve it automatically...")
                await self.get_public_key(recipient)

        # Wait a little to ensure public keys are received
        await asyncio.sleep(1)  # Adjust as needed

        # Check that we have all recipients' public keys
        missing_recipients = [recipient for recipient in recipients if recipient not in self.received_user_public_keys]
        if missing_recipients:
            logger.error(f"Failed to retrieve public keys for users: {', '.join(missing_recipients)}. Cannot send message.")
            return

        try:
            # Generate AES key and IV
            aes_key = os.urandom(32)  # 256 bits
            iv = os.urandom(16)       # 128 bits

            # Prepare the 'chat' payload
            chat_payload = {
                "participants": [self.username] + recipients,
                "message": message
            }
            chat_payload_json = json.dumps(chat_payload)

            # AES-GCM encryption
            encryptor = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(iv),
            ).encryptor()
            ciphertext = encryptor.update(chat_payload_json.encode('utf-8')) + encryptor.finalize()
            tag = encryptor.tag

            # Append the tag to the ciphertext
            encrypted_chat = base64.b64encode(ciphertext + tag).decode('utf-8')

            # Encrypt AES key with each participant's RSA-OAEP public key
            symm_keys = []
            participants = [self.username] + recipients  # Include sender in participants
            for recipient in participants:
                if recipient == self.username:
                    recipient_public_key = self.private_key.public_key()
                else:
                    recipient_public_key = self.received_user_public_keys[recipient]
                encrypted_key = recipient_public_key.encrypt(
                    aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                symm_keys.append(base64.b64encode(encrypted_key).decode('utf-8'))

            # Prepare the data structure
            data = {
                "type": "chat",
                "iv": base64.b64encode(iv).decode('utf-8'),
                "symm_keys": symm_keys,
                "participants": participants,
                "chat": encrypted_chat
            }

            signed_data = self.create_signed_data(data)
            await self.send_signed_message(signed_data)
            logger.debug(f"Sent group message to {', '.join(recipients)}.")
        except Exception as e:
            logger.error(f"Failed to send group message to {', '.join(recipients)}: {e}")

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
            logger.error(f"Failed to decrypt AES key from {sender}: {e}")
            return None

        # Separate ciphertext and tag
        ciphertext = encrypted_message[:-16]  # Last 16 bytes are the tag
        tag = encrypted_message[-16:]

        # Debugging
        logger.debug(f"Ciphertext length: {len(ciphertext)} bytes")
        logger.debug(f"Tag length: {len(tag)} bytes")

        # AES-GCM decryption with tag
        try:
            decryptor = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(iv, tag),
            ).decryptor()
            decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
            return decrypted_message.decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to decrypt message from {sender}: {e}")
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
                            logger.debug(f"Uploaded file {filename}: {file_url}")
                        else:
                            error = await resp.text()
                            print(f"Failed to upload file: {error}")
                            logger.error(f"Failed to upload file {filename}: {error}")
                except Exception as e:
                    logger.error(f"Exception during file upload: {e}")
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
                        logger.debug(f"Downloaded file from {file_url} to {file_path}")
                    else:
                        error = await resp.text()
                        print(f"Failed to download file: {error}")
                        logger.error(f"Failed to download file from {file_url}: {error}")
            except Exception as e:
                logger.error(f"Exception during file download: {e}")
                print(f"Exception during file download: {e}")

    async def get_public_key(self, target_username):
        data = {
            "type": "get_public_key",
            "username": target_username,
            "requesting_username": self.username  # Include your own username
        }
        signed_data = self.create_signed_data(data)
        await self.send_signed_message(signed_data)
        logger.debug(f"Requested public key for {target_username}.")

    def show_help(self):
        help_text = """
Available commands:
    /list                                        - Show online users.
    /broadcast <message>                         - Send a broadcast message.
    /msg <username1,username2,...> <message>     - Send a private message to a user.
    /upload <filepath>                           - Upload a file to the server.
    /download <file_url>                         - Download a file from the server.
    /get_public_key <username>                   - Retrieve the public key of a user.
    /help                                        - Show this help message.
    quit                                         - Exit the chat.
        """
        print(help_text)
        logger.trace("Displayed help information.")

async def start_client(host='localhost', port=8000):
    # Define HTTP URI automatically
    server_ws_uri = f"ws://{host}:{port}"
    server_http_uri = f"http://{host}:{port + 100}"

    client = Client(server_ws_uri, server_http_uri)
    await client.start()

if __name__ == "__main__":
    # Set up command-line arguments
    parser = argparse.ArgumentParser(description="Start the chat client.")
    parser.add_argument("-p", "--port", type=int, default=8000, help="WebSocket server port (default: 8000)")
    parser.add_argument("--host", type=str, default="localhost", help="Server host (default: localhost)")

    args = parser.parse_args()

    # Start the client
    try:
        asyncio.run(start_client(host=args.host, port=args.port))
    except KeyboardInterrupt:
        logger.system("Client closed.")