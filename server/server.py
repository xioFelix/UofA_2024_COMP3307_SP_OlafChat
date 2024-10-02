# server.py
import asyncio
import json
import os
import base64
import argparse
import websockets
import uuid
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from websockets import serve
from aiohttp import web

from src import ui
logger = ui.init_logger('server')   # Initialize logger
ui.set_log_level(logger, 'INFO')   # SET LOG LEVEL AT HERE

# Global state
online_users = {}     # username -> websocket
user_public_keys = {} # username -> public_key (RSA public key object)
last_counters = {}    # username -> last received counter
neighbor_connections = {}  # address -> websocket
global_user_map = {}       # username -> server_address
processed_message_ids = set()

self_host = ''  # Server's own host address
self_port = 0   # Server's own port

# File storage directory
FILE_STORAGE_DIR = "server_files"
os.makedirs(FILE_STORAGE_DIR, exist_ok=True)

# Load or generate server's RSA key pair
def load_or_generate_server_keys():
    if os.path.exists("server_private_key.pem"):
        with open("server_private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None
            )
        logger.trace("Loaded existing private key from server_private_key.pem.")
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open("server_private_key.pem", "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        logger.info("Generated new private key and saved to server_private_key.pem.")
    return private_key


server_private_key = load_or_generate_server_keys()
server_public_key_pem = (
    server_private_key.public_key()
    .public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    .decode("utf-8")
)

# Utility functions
def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("utf-8")


def verify_signature(public_key, message, signature_b64):
    signature = base64.b64decode(signature_b64)
    try:
        public_key.verify(
            signature,
            message.encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        return True
    except Exception as e:
        logger.warning(f"Signature verification failed: {e}")
        return False


def encrypt_message(message_json, recipient_public_key):
    try:
        aes_key = os.urandom(32)  # 256 bits
        iv = os.urandom(16)  # 128 bits

        encryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv),
        ).encryptor()
        ciphertext = (
            encryptor.update(message_json.encode("utf-8")) + encryptor.finalize()
        )
        tag = encryptor.tag

        encrypted_message = ciphertext + tag

        encrypted_key = recipient_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        encrypted_payload = {
            "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
            "iv": base64.b64encode(iv).decode("utf-8"),
            "encrypted_message": base64.b64encode(encrypted_message).decode("utf-8"),
        }

        logger.trace(f"Ciphertext length: {len(ciphertext)} bytes")
        logger.trace(f"Tag length: {len(tag)} bytes")
        logger.trace(
            f"Encrypted message length (ciphertext + tag): {len(encrypted_message)} bytes"
        )

        return json.dumps(encrypted_payload)
    except Exception as e:
        logger.warning(f"Encryption failed: {e}")
        raise


def decrypt_message(encrypted_payload_json, recipient_private_key):
    try:
        payload = json.loads(encrypted_payload_json)
        encrypted_key = base64.b64decode(payload["encrypted_key"])
        iv = base64.b64decode(payload["iv"])
        encrypted_message = base64.b64decode(payload["encrypted_message"])

        aes_key = recipient_private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        ciphertext = encrypted_message[:-16]
        tag = encrypted_message[-16:]

        logger.debug(f"Ciphertext length: {len(ciphertext)} bytes")
        logger.debug(f"Tag length: {len(tag)} bytes")

        decryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv, tag),
        ).decryptor()
        decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

        return decrypted_message.decode("utf-8")
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise


async def connect_to_neighbors(neighbor_addresses, host, port):
    for address in neighbor_addresses:
        asyncio.create_task(connect_to_neighbor(address, host, port))

async def server_handler(websocket, path):
    """
    Handle incoming messages from neighbor servers.

    This function processes messages received from neighbor servers, such as 'message_forward' and other control messages.
    """
    async for message in websocket:
        try:
            data = json.loads(message)
            msg_type = data.get("type")

            if msg_type == "message_forward":
                # Handle forwarded messages
                message_type = data.get("message_type")
                forwarded_data = data.get("data")
                original_sender = data.get("original_sender")

                # Process the message based on its type
                if message_type == "private_message":
                    await process_private_message_forward(forwarded_data)
                elif message_type == "chat":
                    await process_chat_message_forward(forwarded_data)
                elif message_type == "get_public_key":
                    await process_get_public_key_forward(forwarded_data, original_sender)
                elif message_type == "broadcast":
                    await process_broadcast_forward(forwarded_data)
                elif message_type == "forward_response":
                    await process_forward_response(forwarded_data)
                else:
                    logger.warning(f"Unhandled forwarded message type: {message_type}")

            elif msg_type == "forward_response":
                # Handle forwarded responses for get_public_key requests
                original_request = data.get("original_request")
                response_data = data.get("data")
                requesting_username = original_request.get("requesting_username")

                # Find the websocket of the requesting client
                client_ws = online_users.get(requesting_username)
                if client_ws:
                    await send_response(client_ws, response_data)
                    logger.debug(f"Forwarded response to {requesting_username}: {response_data}")
                else:
                    logger.warning(f"Requesting client {requesting_username} not found.")

            elif msg_type == "server_hello":
                # Handle server_hello message
                logger.info(f"Received server_hello from {data.get('sender')}")
                # Optionally send back client_update
                await send_client_update(websocket)

            elif msg_type == "client_update":
                # Update online_users based on received data
                username = data.get("username")
                public_key_pem = data.get("public_key")
                server_address = data.get("server_address")
                if username and public_key_pem and server_address:
                    # Update user_public_keys and global_user_map
                    user_public_keys[username] = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
                    global_user_map[username] = server_address
                    logger.info(f"Updated user {username} info from neighbor server.")
                else:
                    logger.warning(f"Received malformed client_update from neighbor server: {data}")

            elif msg_type == "client_removal":
                username = data.get("username")
                if username and username in global_user_map:
                    del global_user_map[username]
                    logger.info(f"Removed user {username} from global_user_map.")

            else:
                logger.warning(f"Unhandled message type from neighbor server: {msg_type}")

        except Exception as e:
            logger.error(f"Error processing message from neighbor server: {e}")

async def process_forward_response(data):
    """
    Process a forwarded response and deliver it to the requesting client.

    Args:
        data (dict): The data containing the response.
    """
    original_request = data.get("original_request")
    response_data = data.get("data")
    requesting_username = original_request.get("requesting_username")

    # Find the websocket of the requesting client
    client_ws = online_users.get(requesting_username)
    if client_ws:
        await send_response(client_ws, response_data)
        logger.debug(f"Forwarded response to {requesting_username}: {response_data}")
    else:
        logger.warning(f"Requesting client {requesting_username} not found.")

async def process_private_message_forward(data):
    """
    Process a forwarded private message and deliver it to the local recipient.

    Args:
        data (dict): The data containing the private message.
    """
    recipient = data.get("to")
    sender = data.get("from")
    message_body = data.get("message")
    counter = data.get("counter")

    if recipient in online_users:
        recipient_ws = online_users[recipient]
        recipient_public_key = user_public_keys.get(recipient)
        if not recipient_public_key:
            logger.warning(f"No public key found for user {recipient}.")
            return

        private_message = {
            "type": "private_message",
            "from": sender,
            "message": message_body,
            "counter": counter,
        }

        try:
            encrypted_payload = encrypt_message(
                json.dumps(private_message), recipient_public_key
            )
            await recipient_ws.send(encrypted_payload)
            logger.debug(f"Forwarded private message from {sender} to {recipient}.")
        except Exception as e:
            logger.error(f"Failed to send forwarded private message: {e}")
    else:
        logger.warning(f"Recipient {recipient} not found on this server.")

async def process_chat_message_forward(data):
    """
    Process a forwarded chat message and deliver it to local recipients.

    Args:
        data (dict): The data containing the chat message.
    """
    sender_username = data.get("from")
    await handle_chat_message(None, sender_username, data)

async def process_get_public_key_forward(data, original_sender):
    """
    Process a forwarded public key request and send the response back to the requesting server.

    Args:
        data (dict): The data containing the public key request.
        original_sender (str): The address of the server that sent the request.
    """
    target_username = data.get("username")
    requesting_username = data.get("requesting_username")

    if target_username in user_public_keys:
        public_key_pem = (
            user_public_keys[target_username]
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )
        response_data = {
            "type": "public_key",
            "username": target_username,
            "public_key": public_key_pem,
        }
        # Send back the response to the original sender server
        await forward_message_to_server("forward_response", {
            "original_request": data,
            "data": response_data
        }, original_sender)
        logger.debug(f"Processed forwarded request for {target_username}, sent response to {original_sender}")
    else:
        # User not found
        response_data = {
            "type": "error",
            "message": f"Public key for {target_username} not found.",
        }
        await forward_message_to_server("forward_response", {
            "original_request": data,
            "data": response_data
        }, original_sender)
        logger.debug(f"User {target_username} not found, sent error response to {original_sender}")

async def process_broadcast_forward(data):
    """
    Process a forwarded broadcast message and deliver it to local users.

    Args:
        data (dict): The data containing the broadcast message.
    """
    message_id = data.get("message_id")
    if not message_id:
        logger.warning("Received broadcast message without message_id.")
        return

    # Check if we've already processed this message
    if message_id in processed_message_ids:
        logger.debug(f"Already processed broadcast message with ID {message_id}. Skipping.")
        return
    processed_message_ids.add(message_id)

    sender = data.get("from")
    message_body = data.get("message")

    # Send to local users
    broadcast_message = {
        "type": "broadcast",
        "from": sender,
        "message": message_body
    }
    for user, ws in online_users.items():
        if user != sender:
            recipient_public_key = user_public_keys.get(user)
            if recipient_public_key:
                try:
                    encrypted_payload = encrypt_message(json.dumps(broadcast_message), recipient_public_key)
                    await ws.send(encrypted_payload)
                    logger.debug(f"Broadcast message from {sender} sent to {user}.")
                except Exception as e:
                    logger.error(f"Failed to send broadcast message to {user}: {e}")
            else:
                logger.warning(f"No public key found for user {user}. Skipping broadcast.")

    # Forward to other neighbor servers
    await forward_broadcast_to_neighbors(data)

async def forward_broadcast_to_neighbors(data):
    """
    Forward the broadcast message to all neighbor servers, avoiding loops.

    Args:
        data (dict): The data containing the broadcast message.
    """
    for neighbor_ws in neighbor_connections.values():
        forward_data = {
            "type": "message_forward",
            "message_type": "broadcast",
            "data": data,
            "original_sender": f"{self_host}:{self_port}"
        }
        await neighbor_ws.send(json.dumps(forward_data))
        logger.debug("Forwarded broadcast message to neighbor server.")

async def forward_request_to_server(data, server_address):
    """
    Forwards a request to another server.

    This function ensures a connection to the target server and sends the given request.
    """
    # Ensure we have a connection to the target server
    if server_address not in neighbor_connections:
        # Establish connection
        target_server_ws_uri = f"ws://{server_address}/server"
        try:
            neighbor_ws = await websockets.connect(target_server_ws_uri)
            neighbor_connections[server_address] = neighbor_ws
            asyncio.create_task(server_handler(neighbor_ws, '/server'))
        except Exception as e:
            logger.warning(f"Failed to connect to target server at {target_server_ws_uri}: {e}")
            return
    else:
        neighbor_ws = neighbor_connections[server_address]

    # Send the request
    forward_data = {
        "type": "forward_request",
        "original_sender": f"{self_host}:{self_port}",
        "data": data
    }
    await neighbor_ws.send(json.dumps(forward_data))
    logger.debug(f"Forwarded request {data['type']} for {data.get('username')} to {server_address}")

async def send_response_to_server(response, server_address):
    """
    Sends a response message to the specified server.

    This function ensures a connection to the target server and sends the given response message.
    """
    # Ensure we have a connection to the target server
    if server_address not in neighbor_connections:
        # Establish connection
        target_server_ws_uri = f"ws://{server_address}/server"
        try:
            neighbor_ws = await websockets.connect(target_server_ws_uri)
            neighbor_connections[server_address] = neighbor_ws
            asyncio.create_task(server_handler(neighbor_ws, '/server'))
        except Exception as e:
            logger.error(f"Failed to connect to target server at {target_server_ws_uri}: {e}")
            return
    else:
        neighbor_ws = neighbor_connections[server_address]

    # Send the response
    await neighbor_ws.send(json.dumps(response))
    logger.debug(f"Sent response to server {server_address}: {response}")

async def handle_get_public_key(websocket, username, data):
    """
    Handle a 'get_public_key' request from a client.

    If the requested user's public key is available locally, send it to the client.
    If the user is on another server, forward the request to the appropriate server.
    """
    target_username = data.get("username")
    requesting_username = data.get("requesting_username") or username  # Use provided requesting_username or current username

    if target_username in user_public_keys:
        public_key_pem = (
            user_public_keys[target_username]
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )

        response = {
            "type": "public_key",
            "username": target_username,
            "public_key": public_key_pem,
        }
        await send_response(websocket, response)
        logger.info(f"Sent public key for {target_username}")
    elif target_username in global_user_map:
        # User is on another server, forward the request
        target_server_address = global_user_map[target_username]
        data['requesting_username'] = requesting_username  # Ensure requesting_username is set
        await forward_request_to_server(data, target_server_address)
    else:
        # User not found
        logger.warning(f"Public key for user '{target_username}' not found.")
        response = {
            "type": "error",
            "message": f"Public key for {target_username} not found.",
        }
        await send_response(websocket, response)

async def server_ws_handler(websocket, path):
    """
    Handle incoming connections from neighbor servers.
    """
    logger.info(f"Neighbor server connected from {websocket.remote_address}")
    try:
        await server_handler(websocket, path)
    except Exception as e:
        logger.error(f"Connection error with neighbor server {websocket.remote_address}: {e}")

async def connect_to_neighbor(address, host, port):
    while True:
        try:
            # Ensure the address includes the /server path
            if not address.endswith('/server'):
                address = address.rstrip('/') + '/server'

            websocket = await websockets.connect(address)
            neighbor_connections[address] = websocket
            logger.info(f"Connected to neighbor server at {address}")

            # Send server_hello message
            data = {
                "type": "server_hello",
                "sender": f"{host}:{port}"
            }
            await websocket.send(json.dumps(data))
            logger.debug(f"Sent server_hello to {address}")

            # Start listening to the neighbor server
            asyncio.create_task(server_handler(websocket, '/server'))

            break  # Exit the loop once connected
        except Exception as e:
            logger.warning(f"Failed to connect to neighbor server at {address}: {e}")
            logger.info(f"Retrying connection to {address} in 5 seconds...")
            await asyncio.sleep(5)

async def send_client_update(websocket):
    """
    Sends individual client updates to a neighbor server.

    This function iterates over all online users and sends their information
    as separate 'client_update' messages to the neighbor server.
    """
    for username, public_key in user_public_keys.items():
        # Only include users connected to this server
        if online_users.get(username) is not None:
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            data = {
                "type": "client_update",
                "username": username,
                "public_key": public_key_pem,
                "server_address": f"{self_host}:{self_port}"
            }
            await websocket.send(json.dumps(data))
            logger.debug(f"Sent client_update for {username} to neighbor server.")

async def handler(websocket, path):
    try:
        await websocket.send(server_public_key_pem)
        logger.debug(f"Sent server public key to {websocket.remote_address}.")

        async for message in websocket:
            try:
                decrypted_json = decrypt_message(message, server_private_key)
                signed_data = json.loads(decrypted_json)

                msg_type = signed_data.get("type")
                data = signed_data.get("data")
                counter = signed_data.get("counter")
                signature = signed_data.get("signature")

                if (
                    msg_type != "signed_data"
                    or not data
                    or counter is None
                    or not signature
                ):
                    logger.warning(
                        f"Malformed message from {websocket.remote_address}: {signed_data}"
                    )
                    continue

                sender_username = get_username_by_websocket(websocket)

                if sender_username:
                    sender_public_key = user_public_keys.get(sender_username)
                    if not sender_public_key:
                        logger.warning(
                            f"No public key found for user {sender_username}."
                        )
                        continue

                    expected_message = json.dumps(data) + str(counter)
                    if not verify_signature(
                        sender_public_key, expected_message, signature
                    ):
                        logger.warning(f"Invalid signature from {sender_username}.")
                        continue

                    last_counter = last_counters.get(sender_username, 0)
                    if counter <= last_counter:
                        logger.warning(
                            f"Replay attack detected from {sender_username}. Counter: {counter}"
                        )
                        continue
                    last_counters[sender_username] = counter

                    await process_signed_data(websocket, data, sender_username)

                else:
                    if data.get("type") in ["hello", "login"]:
                        await process_signed_data_initial(
                            websocket, data, counter, signature
                        )
                    else:
                        logger.warning(
                            f"Unauthenticated message from {websocket.remote_address}: {data.get('type')}"
                        )
                        continue

            except Exception as e:
                logger.error(
                    f"Error processing message from {websocket.remote_address}: {e}"
                )
                await websocket.close(code=1011, reason="Internal server error")
                break

    except Exception as e:
        logger.error(f"Connection error with {websocket.remote_address}: {e}")
    finally:
        username = get_username_by_websocket(websocket)
        if username:
            del online_users[username]
            del user_public_keys[username]
            del last_counters[username]
            if username in global_user_map:
                del global_user_map[username]
            logger.info(
                f"User {username} disconnected. Online users: {set(online_users.keys())}"
            )
            # Broadcast client removal
            await broadcast_client_removal(username)

async def broadcast_client_removal(username):
    """
    Broadcasts a client removal to all neighbor servers.

    This function informs neighbor servers that a user has disconnected.
    """
    data = {
        "type": "client_removal",
        "username": username,
        "server_address": f"{self_host}:{self_port}"
    }
    for neighbor_ws in neighbor_connections.values():
        await neighbor_ws.send(json.dumps(data))
        logger.debug(f"Broadcasted client_removal for {username} to neighbor server.")

def get_username_by_websocket(websocket):
    for user, ws in online_users.items():
        if ws == websocket:
            return user
    return None

async def process_signed_data_initial(websocket, data, counter, signature):
    """
    Process initial signed data from an unauthenticated user.

    This function handles 'hello' and 'login' messages from users who are not yet authenticated.
    It loads the user's public key, stores it, and updates the online users list.
    For 'login' messages, it also updates the global user map and notifies neighbor servers.
    """
    msg_type = data.get("type")
    username = data.get("username")
    public_key_pem = data.get("public_key")

    if not username or not public_key_pem:
        logger.warning("Hello/Login message missing username or public_key.")
        response = {
            "type": "status",
            "status": "error",
            "message": "Missing username or public_key.",
        }
        await send_response(websocket, response)
        return

    if username in online_users:
        logger.warning(f"Username {username} already online.")
        response = {
            "type": "status",
            "status": "error",
            "message": "Username already online.",
        }
        await send_response(websocket, response)
        return

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        logger.debug(f"Loaded public key for user {username}.")
    except Exception as e:
        logger.warning(f"Invalid public key format from {username}: {e}")
        response = {
            "type": "status",
            "status": "error",
            "message": "Invalid public key format.",
        }
        await send_response(websocket, response)
        return

    if msg_type == "hello":
        online_users[username] = websocket
        user_public_keys[username] = public_key
        logger.info(
            f"User {username} connected. Online users: {set(online_users.keys())}"
        )

        response = {"type": "status", "status": "success", "message": "Hello received."}
        await send_response(websocket, response)

    elif msg_type == "login":
        online_users[username] = websocket
        user_public_keys[username] = public_key
        logger.info(
            f"User {username} logged in successfully. Online users: {set(online_users.keys())}"
        )

        # Update global_user_map with user's server address
        global_user_map[username] = f"{self_host}:{self_port}"
        # Notify neighbor servers about the new user
        await broadcast_client_update(username, public_key_pem)

        response = {
            "type": "status",
            "status": "success",
            "message": "Logged in successfully.",
        }
        await send_response(websocket, response)

async def broadcast_client_update(username, public_key_pem):
    """
    Broadcasts a client update to all neighbor servers.

    This function sends a 'client_update' message to all connected neighbor servers,
    informing them about a new user who has logged in, along with their public key and server address.
    """
    data = {
        "type": "client_update",
        "username": username,
        "public_key": public_key_pem,
        "server_address": f"{self_host}:{self_port}"
    }
    for neighbor_ws in neighbor_connections.values():
        await neighbor_ws.send(json.dumps(data))
        logger.debug(f"Broadcasted client_update for {username} to neighbor server.")

# Added function to handle get_public_key
async def handle_get_public_key(websocket, username, data):
    target_username = data.get("username")
    if target_username in user_public_keys:
        public_key_pem = (
            user_public_keys[target_username]
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )

        response = {
            "type": "public_key",
            "username": target_username,
            "public_key": public_key_pem,
        }
        await send_response(websocket, response)
        logger.info(f"Sent public key for {target_username}")
    else:
        logger.warning(f"Public key for user '{target_username}' not found.")
        response = {
            "type": "error",
            "message": f"Public key for {target_username} not found.",
        }
        await send_response(websocket, response)

async def handle_broadcast(websocket, username, message_body):
    if not message_body:
        logger.warning(f"Broadcast message missing body from {username}.")
        response = {"type": "status", "status": "error", "message": "Broadcast message missing body."}
        await send_response(websocket, response)
        return

    broadcast_message = {
        "type": "broadcast",
        "from": username,
        "message": message_body
    }

    # Send to local users
    for user, ws in online_users.items():
        if user != username:
            recipient_public_key = user_public_keys.get(user)
            if recipient_public_key:
                try:
                    encrypted_payload = encrypt_message(json.dumps(broadcast_message), recipient_public_key)
                    await ws.send(encrypted_payload)
                    logger.debug(f"Broadcast message sent to {user}.")
                except Exception as e:
                    logger.error(f"Failed to send broadcast message to {user}: {e}")
                    continue
            else:
                logger.warning(f"No public key found for user {user}. Skipping broadcast.")

    # Forward the broadcast message to neighbor servers
    data = {
        "from": username,
        "message": message_body,
        "message_id": str(uuid.uuid4())
    }
    await forward_broadcast_to_neighbors(data)

    response = {
        "type": "status",
        "status": "success",
        "message": "Broadcast message sent successfully."
    }
    await send_response(websocket, response)

async def handle_chat_message(websocket, username, data):
    """
    Handle a 'chat' message sent by a user to multiple recipients.

    Args:
        websocket: The websocket of the sender (can be None).
        username (str): The username of the sender.
        data (dict): The data containing the chat message.
    """
    iv = data.get("iv")
    symm_keys = data.get("symm_keys")
    participants = data.get("participants")
    encrypted_chat = data.get("chat")

    if not iv or not symm_keys or not participants or not encrypted_chat:
        logger.warning(f"Chat message from {username} missing fields.")
        if websocket:
            response = {
                "type": "status",
                "status": "error",
                "message": "Missing fields in chat message.",
            }
            await send_response(websocket, response)
        return

    # Send the message to all participants except the sender
    for idx, recipient in enumerate(participants):
        if recipient == username:
            continue  # Skip sending to self

        # Check if recipient is connected to this server
        if recipient in online_users:
            recipient_ws = online_users[recipient]
            recipient_public_key = user_public_keys.get(recipient)
            if not recipient_public_key:
                logger.warning(f"No public key found for user {recipient}.")
                continue

            # Prepare the message for the recipient
            recipient_symm_keys = [''] * len(participants)
            recipient_symm_keys[idx] = symm_keys[idx]  # Set the recipient's own symm_key

            chat_message = {
                "type": "chat",
                "iv": iv,
                "symm_keys": recipient_symm_keys,
                "participants": participants,
                "chat": encrypted_chat
            }

            try:
                # Encrypt the message for the recipient
                encrypted_payload = encrypt_message(json.dumps(chat_message), recipient_public_key)
                await recipient_ws.send(encrypted_payload)
                logger.debug(f"Chat message from {username} sent to {recipient}.")
            except Exception as e:
                logger.error(f"Failed to send chat message from {username} to {recipient}: {e}")
                continue

        elif recipient in global_user_map:
            # Recipient is connected to another server, forward the message
            target_server_address = global_user_map[recipient]
            data['from'] = username  # Ensure 'from' field is set
            await forward_message_to_server("chat", data, target_server_address)
            logger.info(f"Forwarded chat message from {username} to {recipient} via server {target_server_address}.")
        else:
            logger.warning(f"Chat message recipient {recipient} not found.")
            continue

    # Optionally, send a confirmation back to the sender
    if websocket:
        response = {
            "type": "status",
            "status": "success",
            "message": "Group message sent successfully."
        }
        await send_response(websocket, response)

async def forward_message_to_server(message_type, data, server_address):
    """
    Forwards a message to another server.

    Args:
        message_type (str): The type of the message to forward.
        data (dict): The message data to forward.
        server_address (str): The address of the target server.
    """
    # Ensure we have a connection to the target server
    if server_address not in neighbor_connections:
        # Establish connection
        target_server_ws_uri = f"ws://{server_address}/server"
        try:
            neighbor_ws = await websockets.connect(target_server_ws_uri)
            neighbor_connections[server_address] = neighbor_ws
            asyncio.create_task(server_handler(neighbor_ws, '/server'))
        except Exception as e:
            logger.error(f"Failed to connect to target server at {target_server_ws_uri}: {e}")
            return
    else:
        neighbor_ws = neighbor_connections[server_address]

    # Send the message
    forward_data = {
        "type": "message_forward",
        "message_type": message_type,
        "data": data,
        "original_sender": f"{self_host}:{self_port}"
    }
    await neighbor_ws.send(json.dumps(forward_data))
    logger.debug(f"Forwarded {message_type} message to {server_address}")

async def process_signed_data(websocket, data, username):
    msg_type = data.get("type")

    if msg_type == "list_users":
        await handle_list_users(websocket, username)
    elif msg_type == "broadcast":
        await handle_broadcast(websocket, username, data.get("body"))
    elif msg_type == "private_message":
        await handle_private_message(websocket, username, data)
    elif msg_type == "chat":
        await handle_chat_message(websocket, username, data)
    elif msg_type == "get_public_key":
        await handle_get_public_key(websocket, username, data)
    elif msg_type == "kick_user":
        await handle_kick_user(websocket, username, data)
    else:
        logger.warning(f"Unhandled message type from {username}: {msg_type}")

async def handle_list_users(websocket, username):
    """
    Sends a list of all online users across the network to the requesting client.

    This function combines local online users and users from the global user map
    to provide a comprehensive list.
    """
    # Combine local and global users
    all_users = set(online_users.keys()).union(set(global_user_map.keys()))
    response = {"type": "client_list", "servers": list(all_users)}
    await send_response(websocket, response)
    logger.debug(f"Sent client list to {username}.")

async def handle_private_message(websocket, username, data):
    recipient = data.get("to")
    message_body = data.get("message")
    counter = data.get("counter")

    if not recipient or not message_body or counter is None:
        logger.warning(f"Private message from {username} missing fields.")
        response = {
            "type": "status",
            "status": "error",
            "message": "Missing fields in private message.",
        }
        await send_response(websocket, response)
        return

    if recipient in online_users:
        # Recipient is online on this server
        recipient_ws = online_users[recipient]
        recipient_public_key = user_public_keys.get(recipient)

        if not recipient_public_key:
            logger.warning(f"No public key found for user {recipient}.")
            response = {
                "type": "status",
                "status": "error",
                "message": f"No public key found for user {recipient}.",
            }
            await send_response(websocket, response)
            return

        private_message = {
            "type": "private_message",
            "from": username,
            "message": message_body,
            "counter": counter,
        }

        try:
            encrypted_payload_for_recipient = encrypt_message(
                json.dumps(private_message), recipient_public_key
            )
            await recipient_ws.send(encrypted_payload_for_recipient)
            logger.debug(f"Private message from {username} sent to {recipient}.")
        except Exception as e:
            logger.error(
                f"Failed to send private message from {username} to {recipient}: {e}"
            )
            response = {
                "type": "status",
                "status": "error",
                "message": f"Failed to send message to {recipient}.",
            }
            await send_response(websocket, response)
    elif recipient in global_user_map:
        # Recipient is on another server, forward the message
        target_server_address = global_user_map[recipient]
        data['from'] = username  # Ensure 'from' field is set
        await forward_message_to_server("private_message", data, target_server_address)
        logger.info(f"Forwarded private message from {username} to {recipient} via server {target_server_address}.")
        response = {
            "type": "status",
            "status": "success",
            "message": f"Message forwarded to {recipient} via server {target_server_address}."
        }
        await send_response(websocket, response)
    else:
        logger.warning(f"Private message recipient {recipient} not found.")
        response = {
            "type": "status",
            "status": "error",
            "message": f"User {recipient} not found.",
        }
        await send_response(websocket, response)

async def forward_message_to_neighbors(message_type, data):
    """
    Forward a message to all neighbor servers.

    Args:
        message_type (str): The type of the message to forward.
        data (dict): The message data to forward.
    """
    for neighbor_ws in neighbor_connections.values():
        forward_data = {
            "type": "message_forward",
            "message_type": message_type,
            "data": data,
            "original_sender": f"{self_host}:{self_port}"
        }
        await neighbor_ws.send(json.dumps(forward_data))
        logger.debug(f"Forwarded {message_type} message to neighbor server.")

async def send_response(websocket, response):
    if websocket is None:
    # Cannot send response without a websocket
        return

    username = get_username_by_websocket(websocket)
    if not username:
        logger.warning("Attempted to send response to unidentified websocket.")
        return

    recipient_public_key = user_public_keys.get(username)
    if not recipient_public_key:
        logger.warning(
            f"No public key found for user {username}. Cannot send response."
        )
        return

    try:
        encrypted_response = encrypt_message(json.dumps(response), recipient_public_key)
        await websocket.send(encrypted_response)
        logger.debug(f"Sent response to {username}: {response}")
    except Exception as e:
        logger.error(f"Failed to send response to {username}: {e}")


# HTTP Handlers for File Upload and Download
async def handle_upload(request):
    reader = await request.multipart()
    field = await reader.next()
    if field.name != "file":
        return web.Response(status=400, text="Expected 'file' field.")

    filename = field.filename
    file_path = os.path.join(FILE_STORAGE_DIR, filename)

    with open(file_path, "wb") as f:
        while True:
            chunk = await field.read_chunk()  # 8192 bytes by default.
            if not chunk:
                break
            f.write(chunk)

    file_url = f"http://{request.host}/files/{filename}"
    logger.info(f"File uploaded: {filename} -> {file_url}")
    return web.json_response(
        {"type": "status", "status": "success", "file_url": file_url}
    )


async def handle_download(request):
    filename = request.match_info.get("filename")
    file_path = os.path.join(FILE_STORAGE_DIR, filename)

    if not os.path.exists(file_path):
        return web.Response(status=404, text="File not found.")

    return web.FileResponse(file_path)

async def handle_kick_user(websocket, username, data):
    """
    Handle a 'kick_user' command sent by an admin user to disconnect a target user.

    Args:
        websocket: The websocket of the sender.
        username (str): The username of the sender.
        data (dict): The data containing the kick command.
    """
    # Only allow the admin user to execute this command
    if username != "admin":
        logger.warning(f"User {username} attempted to use kick command without permission.")
        response = {
            "type": "status",
            "status": "error",
            "message": "You do not have permission to use this command."
        }
        await send_response(websocket, response)
        return

    target_username = data.get("target")
    if not target_username:
        logger.warning("Kick command missing target username.")
        response = {
            "type": "status",
            "status": "error",
            "message": "Missing target username."
        }
        await send_response(websocket, response)
        return

    # Check if the target user is online
    target_websocket = online_users.get(target_username)
    if not target_websocket:
        logger.warning(f"Target user {target_username} not online.")
        response = {
            "type": "status",
            "status": "error",
            "message": f"User {target_username} not online."
        }
        await send_response(websocket, response)
        return

    # Forcefully disconnect the target user
    try:
        await target_websocket.close(code=4000, reason="You have been kicked by the admin.")
    except Exception as e:
        logger.error(f"Error closing websocket for user {target_username}: {e}")

    # Remove user from online users
    online_users.pop(target_username, None)
    user_public_keys.pop(target_username, None)
    last_counters.pop(target_username, None)
    logger.info(f"User {target_username} has been kicked by admin.")

    # Send success response to admin
    response = {
        "type": "status",
        "status": "success",
        "message": f"User {target_username} has been kicked."
    }
    await send_response(websocket, response)

def start_http_server():
    app = web.Application()
    app.router.add_post("/api/upload", handle_upload)
    app.router.add_get("/files/{filename}", handle_download)
    return app

async def start(port=8000, host='0.0.0.0', neighbor_addresses=None):
    global self_host, self_port
    # Set self_host to '127.0.0.1' if host is '0.0.0.0', else use the specified host
    if host == '0.0.0.0':
        self_host = '127.0.0.1'
    else:
        self_host = host
    self_port = port

    # Start the HTTP server before starting the WebSocket server
    app = start_http_server()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port + 100)
    await site.start()
    logger.system(f"HTTP server started on http://{host}:{port + 100}")

    # Start the WebSocket server using 'async with'
    async def main_handler(websocket, path):
        if path == '/client':
            await handler(websocket, path)
        elif path == '/server':
            await server_handler(websocket, path)
        else:
            logger.warning(f"Unknown path {path}, rejecting connection.")
            await websocket.close(code=1000, reason='Unknown path')

    async with serve(main_handler, host, port):
        logger.system(f"WebSocket server started on ws://{host}:{port}")

        # Connect to neighbor servers
        if neighbor_addresses:
            asyncio.create_task(connect_to_neighbors(neighbor_addresses, host, port))

        await asyncio.Future()  # Keep the server running

async def close():
    # Add code to properly close WebSocket and HTTP server, and cleanup if necessary
    logger.system("Shutting down servers...")
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    [task.cancel() for task in tasks]
    await asyncio.gather(*tasks, return_exceptions=True)

if __name__ == "__main__":
    # Setup argument parser
    parser = argparse.ArgumentParser(description="Start the WebSocket and HTTP server.")
    parser.add_argument("-p", "--port", type=int, default=8000, help="WebSocket server port (default: 8000)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind the servers (default: 0.0.0.0)")
    parser.add_argument("--neighbors", type=str, nargs='*', help="List of neighbor server addresses (e.g., ws://localhost:8001)")

    args = parser.parse_args()

    # Use the arguments to start
    try:
        asyncio.run(start(port=args.port, host=args.host, neighbor_addresses=args.neighbors))
    except KeyboardInterrupt:
        asyncio.run(close())
        logger.trace("Server closed.")
