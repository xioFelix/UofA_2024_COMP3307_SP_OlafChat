# server.py

import asyncio
import json
import logging
import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from websockets import serve
from aiohttp import web

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG for detailed logs
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Global state
online_users = {}          # username -> websocket
user_public_keys = {}     # username -> public_key (RSA public key object)
last_counters = {}        # username -> last received counter

# File storage directory
FILE_STORAGE_DIR = 'server_files'
os.makedirs(FILE_STORAGE_DIR, exist_ok=True)

# Load or generate server's RSA key pair
def load_or_generate_server_keys():
    if os.path.exists("server_private_key.pem"):
        with open("server_private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        logging.info("Loaded existing private key from server_private_key.pem.")
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        with open("server_private_key.pem", "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
        logging.info("Generated new private key and saved to server_private_key.pem.")
    return private_key

server_private_key = load_or_generate_server_keys()
server_public_key_pem = server_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

# Utility functions
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

async def handler(websocket, path):
    try:
        # Send server's public key
        await websocket.send(server_public_key_pem)
        logging.debug(f"Sent server public key to {websocket.remote_address}.")

        async for message in websocket:
            try:
                # Decrypt incoming message
                decrypted_json = decrypt_message(message, server_private_key)
                signed_data = json.loads(decrypted_json)

                # Extract fields
                msg_type = signed_data.get("type")
                data = signed_data.get("data")
                counter = signed_data.get("counter")
                signature = signed_data.get("signature")

                if msg_type != "signed_data" or not data or counter is None or not signature:
                    logging.warning(f"Malformed message from {websocket.remote_address}: {signed_data}")
                    continue

                # Determine if the user is already identified
                sender_username = get_username_by_websocket(websocket)

                if sender_username:
                    # User is identified; retrieve public key
                    sender_public_key = user_public_keys.get(sender_username)
                    if not sender_public_key:
                        logging.warning(f"No public key found for user {sender_username}.")
                        continue

                    # Verify signature
                    expected_message = json.dumps(data) + str(counter)
                    if not verify_signature(sender_public_key, expected_message, signature):
                        logging.warning(f"Invalid signature from {sender_username}.")
                        continue

                    # Prevent replay attacks
                    last_counter = last_counters.get(sender_username, 0)
                    if counter <= last_counter:
                        logging.warning(f"Replay attack detected from {sender_username}. Counter: {counter}")
                        continue
                    last_counters[sender_username] = counter

                    # Process message
                    await process_signed_data(websocket, data, sender_username)

                else:
                    # User is not identified; expect 'hello' or 'login' messages
                    if data.get("type") in ["hello", "login"]:
                        await process_signed_data_initial(websocket, data, counter, signature)
                    else:
                        logging.warning(f"Unauthenticated message from {websocket.remote_address}: {data.get('type')}")
                        continue

            except Exception as e:
                logging.error(f"Error processing message from {websocket.remote_address}: {e}")
                await websocket.close(code=1011, reason="Internal server error")
                break

    except Exception as e:
        logging.error(f"Connection error with {websocket.remote_address}: {e}")
    finally:
        # Handle disconnection
        username = get_username_by_websocket(websocket)
        if username:
            del online_users[username]
            del user_public_keys[username]
            del last_counters[username]
            logging.info(f"User {username} disconnected. Online users: {set(online_users.keys())}")

def get_username_by_websocket(websocket):
    for user, ws in online_users.items():
        if ws == websocket:
            return user
    return None

async def process_signed_data_initial(websocket, data, counter, signature):
    msg_type = data.get("type")
    username = data.get("username")
    public_key_pem = data.get("public_key")

    if not username or not public_key_pem:
        logging.warning("Hello/Login message missing username or public_key.")
        response = {"type": "status", "status": "error", "message": "Missing username or public_key."}
        await send_response(websocket, response)
        return

    if username in online_users:
        logging.warning(f"Username {username} already online.")
        response = {"type": "status", "status": "error", "message": "Username already online."}
        await send_response(websocket, response)
        return

    # Load public key
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        logging.debug(f"Loaded public key for user {username}.")
    except Exception as e:
        logging.warning(f"Invalid public key format from {username}: {e}")
        response = {"type": "status", "status": "error", "message": "Invalid public key format."}
        await send_response(websocket, response)
        return

    if msg_type == "hello":
        # Register new user
        online_users[username] = websocket
        user_public_keys[username] = public_key
        logging.info(f"User {username} connected. Online users: {set(online_users.keys())}")

        # Send acknowledgment
        response = {"type": "status", "status": "success", "message": "Hello received."}
        await send_response(websocket, response)

    elif msg_type == "login":
        # Authenticate user (simplified for example)
        online_users[username] = websocket
        user_public_keys[username] = public_key
        logging.info(f"User {username} logged in successfully. Online users: {set(online_users.keys())}")

        # Send success response
        response = {"type": "status", "status": "success", "message": "Logged in successfully."}
        await send_response(websocket, response)

async def process_signed_data(websocket, data, username):
    msg_type = data.get("type")

    if msg_type == "list_users":
        await handle_list_users(websocket, username)
    elif msg_type == "broadcast":
        await handle_broadcast(websocket, username, data.get("body"))
    elif msg_type == "private_message":
        await handle_private_message(websocket, username, data)
    else:
        logging.warning(f"Unhandled message type from {username}: {msg_type}")

async def handle_list_users(websocket, username):
    users = list(online_users.keys())
    response = {"type": "client_list", "servers": users}
    await send_response(websocket, response)
    logging.debug(f"Sent client list to {username}.")

async def handle_broadcast(websocket, username, message_body):
    if not message_body:
        logging.warning(f"Broadcast message missing body from {username}.")
        return

    broadcast_message = {
        "type": "broadcast",
        "from": username,
        "message": message_body
    }

    # Encrypt broadcast message for each user and send
    for user, ws in online_users.items():
        if user != username:
            recipient_public_key = user_public_keys.get(user)
            if recipient_public_key:
                try:
                    encrypted_payload = encrypt_message(json.dumps(broadcast_message), recipient_public_key)
                    await ws.send(encrypted_payload)
                    logging.debug(f"Broadcast message sent to {user}.")
                except Exception as e:
                    logging.error(f"Failed to send broadcast message to {user}: {e}")

async def handle_private_message(websocket, username, data):
    recipient = data.get("to")
    encrypted_payload = data.get("message")
    counter = data.get("counter")

    if not recipient or not encrypted_payload or counter is None:
        logging.warning(f"Private message from {username} missing fields.")
        response = {"type": "status", "status": "error", "message": "Missing fields in private message."}
        await send_response(websocket, response)
        return

    if recipient not in online_users:
        logging.warning(f"Private message recipient {recipient} not online.")
        response = {"type": "status", "status": "error", "message": f"User {recipient} not online."}
        await send_response(websocket, response)
        return

    recipient_ws = online_users[recipient]
    recipient_public_key = user_public_keys.get(recipient)
    if not recipient_public_key:
        logging.warning(f"No public key found for user {recipient}.")
        response = {"type": "status", "status": "error", "message": f"No public key found for user {recipient}."}
        await send_response(websocket, response)
        return

    private_message = {
        "type": "private_message",
        "from": username,
        "message": encrypted_payload,
        "counter": counter
    }

    try:
        encrypted_payload_for_recipient = encrypt_message(json.dumps(private_message), recipient_public_key)
        await recipient_ws.send(encrypted_payload_for_recipient)
        logging.debug(f"Private message from {username} sent to {recipient}.")
    except Exception as e:
        logging.error(f"Failed to send private message from {username} to {recipient}: {e}")
        response = {"type": "status", "status": "error", "message": f"Failed to send message to {recipient}."}
        await send_response(websocket, response)

async def send_response(websocket, response):
    # Determine the recipient's public key
    username = get_username_by_websocket(websocket)
    if not username:
        logging.warning("Attempted to send response to unidentified websocket.")
        return

    recipient_public_key = user_public_keys.get(username)
    if not recipient_public_key:
        logging.warning(f"No public key found for user {username}. Cannot send response.")
        return

    try:
        # Encrypt the response
        encrypted_response = encrypt_message(json.dumps(response), recipient_public_key)
        await websocket.send(encrypted_response)
        logging.debug(f"Sent response to {username}: {response}")
    except Exception as e:
        logging.error(f"Failed to send response to {username}: {e}")

# HTTP Handlers for File Upload and Download
async def handle_upload(request):
    reader = await request.multipart()
    field = await reader.next()
    if field.name != 'file':
        return web.Response(status=400, text="Expected 'file' field.")

    filename = field.filename
    file_path = os.path.join(FILE_STORAGE_DIR, filename)

    with open(file_path, 'wb') as f:
        while True:
            chunk = await field.read_chunk()  # 8192 bytes by default.
            if not chunk:
                break
            f.write(chunk)

    file_url = f"http://{request.host}/files/{filename}"
    logging.info(f"File uploaded: {filename} -> {file_url}")
    return web.json_response({"type": "status", "status": "success", "file_url": file_url})

async def handle_download(request):
    filename = request.match_info.get('filename')
    file_path = os.path.join(FILE_STORAGE_DIR, filename)

    if not os.path.exists(file_path):
        return web.Response(status=404, text="File not found.")

    return web.FileResponse(file_path)

def start_http_server():
    app = web.Application()
    app.router.add_post('/api/upload', handle_upload)
    app.router.add_get('/files/{filename}', handle_download)
    return app

async def main():
    # Start WebSocket server
    ws_server = serve(handler, "0.0.0.0", 8080)
    asyncio.ensure_future(ws_server)
    logging.info("WebSocket server started on ws://0.0.0.0:8080")

    # Start HTTP server for file transfers
    app = start_http_server()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 8000)
    await site.start()
    logging.info("HTTP server started on http://0.0.0.0:8000")

    # Run forever
    await asyncio.Future()  # Run forever

if __name__ == "__main__":
    asyncio.run(main())
