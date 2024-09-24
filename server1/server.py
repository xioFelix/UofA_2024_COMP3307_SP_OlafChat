# server.py

import asyncio
import json
import logging
import os
import base64
import hashlib
import argparse
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from aiohttp import web, ClientSession, WSMsgType
import websockets
from websockets.exceptions import ConnectionClosed
import signal

# 配置日志
logging.basicConfig(
    level=logging.DEBUG,  # 设置为 DEBUG 以获取详细日志
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# 全局状态
online_users = {}                # fingerprint -> websocket
user_public_keys = {}            # fingerprint -> public_key (RSA public key object)
last_counters = {}               # fingerprint -> last received counter
fingerprint_to_username = {}     # fingerprint -> username
username_to_fingerprint = {}     # username -> fingerprint
connected_neighbours = {}        # server_address -> websocket
server_psk = "YourPreSharedKey"  # 预共享密钥，用于服务器间身份验证

# 文件存储目录
FILE_STORAGE_DIR = 'server_files'
os.makedirs(FILE_STORAGE_DIR, exist_ok=True)

# 加载或生成服务器的 RSA 密钥对
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

# 工具函数
def compute_fingerprint(public_key):
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fingerprint = hashlib.sha256(public_key_bytes).digest()
    return fingerprint

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
        logging.info("Signature verified successfully.")
        return True
    except Exception as e:
        logging.error(f"Signature verification failed: {e}")
        return False

def encrypt_message(message, recipient_public_key):
    """
    使用接收者的公钥和 AES-GCM 对称加密加密消息。
    """
    try:
        # 生成 AES 密钥和 nonce
        aes_key = os.urandom(32)  # 256 位
        nonce = os.urandom(12)    # 96 位，用于 GCM

        # AES-GCM 加密
        encryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(nonce),
        ).encryptor()
        ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
        tag = encryptor.tag

        # 使用 RSA-OAEP 加密 AES 密钥
        encrypted_key = recipient_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 准备负载
        message_package = {
            "encrypted_key": base64.b64encode(encrypted_key).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8')
        }
        return json.dumps(message_package)
    except Exception as e:
        logging.error(f"Encryption failed: {e}")
        raise

def decrypt_message(message_package_json, private_key):
    """
    使用接收者的私钥和 AES-GCM 对称解密接收到的消息。
    """
    try:
        message_package = json.loads(message_package_json)
        encrypted_key = base64.b64decode(message_package["encrypted_key"])
        nonce = base64.b64decode(message_package["nonce"])
        ciphertext = base64.b64decode(message_package["ciphertext"])
        tag = base64.b64decode(message_package["tag"])

        # 使用 RSA-OAEP 解密 AES 密钥
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # AES-GCM 解密
        decryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(nonce, tag),
        ).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext.decode('utf-8')
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        raise

def get_fingerprint_by_username(username):
    fingerprint = username_to_fingerprint.get(username)
    return fingerprint

def get_username_by_fingerprint(fingerprint):
    return fingerprint_to_username.get(fingerprint, "Unknown")

async def handle_client_websocket(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    # 发送服务器的公钥
    await ws.send_str(server_public_key_pem)
    logging.debug(f"Sent server public key to {request.remote}.")

    async for msg in ws:
        if msg.type == WSMsgType.TEXT:
            try:
                # 解密收到的消息
                decrypted_json = decrypt_message(msg.data, server_private_key)
                signed_data = json.loads(decrypted_json)

                # 提取字段
                msg_type = signed_data.get("type")
                data = signed_data.get("data")
                counter_ = signed_data.get("counter")
                signature = signed_data.get("signature")

                if msg_type != "signed_data" or not data or counter_ is None or not signature:
                    logging.warning(f"Malformed message from {request.remote}: {signed_data}")
                    continue

                # 判断用户是否已经认证
                sender_fingerprint = get_fingerprint_by_websocket(ws)

                if sender_fingerprint:
                    # 用户已认证；获取公钥
                    sender_public_key = user_public_keys.get(sender_fingerprint)
                    if not sender_public_key:
                        logging.warning(f"No public key found for fingerprint {sender_fingerprint.hex()}.")
                        continue

                    # 验证签名
                    expected_message = json.dumps(data) + str(counter_)
                    if not verify_signature(sender_public_key, expected_message, signature):
                        logging.warning(f"Invalid signature from fingerprint {sender_fingerprint.hex()}.")
                        continue

                    # 防止重放攻击
                    last_counter = last_counters.get(sender_fingerprint, 0)
                    if counter_ <= last_counter:
                        logging.warning(f"Replay attack detected from fingerprint {sender_fingerprint.hex()}. Counter: {counter_}")
                        continue
                    last_counters[sender_fingerprint] = counter_

                    # 处理消息
                    await process_signed_data(ws, data, sender_fingerprint)

                else:
                    # 用户未认证；期望 'hello' 或 'login' 消息
                    msg_type_initial = data.get("type")
                    if msg_type_initial in ["hello", "login"]:
                        await process_signed_data_initial(ws, data, counter_, signature)
                    else:
                        logging.warning(f"Unauthenticated message from {request.remote}: {msg_type_initial}")
                        continue

            except Exception as e:
                logging.error(f"Error processing message from {request.remote}: {e}")
                await ws.close(code=1011, message="Internal server error")
        elif msg.type == WSMsgType.ERROR:
            logging.error(f"WebSocket connection closed with exception {ws.exception()}")

    # 处理断开连接
    fingerprint = get_fingerprint_by_websocket(ws)
    if fingerprint:
        username = fingerprint_to_username.get(fingerprint, "Unknown")
        del online_users[fingerprint]
        del user_public_keys[fingerprint]
        del last_counters[fingerprint]
        del fingerprint_to_username[fingerprint]
        del username_to_fingerprint[username]
        logging.info(f"User {username} disconnected. Online users: {[fp.hex() for fp in online_users.keys()]}")

    return ws

async def handle_neighbour_websocket(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    try:
        # 接收 PSK
        received_psk = await ws.receive_str()
        if received_psk != server_psk:
            logging.error(f"Neighbour server authentication failed: Invalid PSK.")
            await ws.close(code=1008, message="Invalid PSK")
            return ws

        # 发送 PSK 回应
        await ws.send_str(server_psk)
        logging.info(f"Authenticated neighbour server at {request.remote}.")

        # 发送服务器的公钥
        await ws.send_str(server_public_key_pem)
        logging.debug(f"Sent server public key to neighbour {request.remote}.")

        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    # 假设来自邻居的消息已经是加密的 JSON
                    decrypted_json = decrypt_message(msg.data, server_private_key)
                    message_data = json.loads(decrypted_json)
                    await process_neighbour_message(message_data)
                except Exception as e:
                    logging.error(f"Error processing neighbour message from {request.remote}: {e}")
            elif msg.type == WSMsgType.ERROR:
                logging.error(f"Neighbour WebSocket connection closed with exception {ws.exception()}")

    except Exception as e:
        logging.error(f"Error in neighbour WebSocket handler: {e}")
    finally:
        if request.remote in connected_neighbours:
            del connected_neighbours[request.remote]
            logging.info(f"Removed neighbour server at {request.remote} from connected neighbours.")

    return ws

async def process_signed_data(ws, data, fingerprint):
    msg_type = data.get("type")

    if msg_type == "list_users":
        await handle_list_users(ws, fingerprint)
    elif msg_type == "broadcast":
        await handle_broadcast(ws, fingerprint, data.get("body"))
    elif msg_type == "private_message":
        await handle_private_message(ws, fingerprint, data)
    elif msg_type == "public_chat":
        await handle_public_chat(ws, fingerprint, data)
    elif msg_type == "chat":
        await handle_group_chat(ws, fingerprint, data)
    elif msg_type == "get_public_key":
        await handle_get_public_key(ws, fingerprint, data)
    else:
        logging.warning(f"Unhandled message type from {fingerprint_to_username.get(fingerprint, 'Unknown')}: {msg_type}")

async def process_signed_data_initial(ws, data, counter_, signature):
    msg_type = data.get("type")
    username_ = data.get("username")
    public_key_pem = data.get("public_key")

    if not username_ or not public_key_pem:
        logging.warning("Hello/Login message missing username or public_key.")
        response = {"type": "status", "status": "error", "message": "Missing username or public_key."}
        await send_response(ws, response)
        return

    # 计算 fingerprint
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        fingerprint_ = compute_fingerprint(public_key)
    except Exception as e:
        logging.warning(f"Invalid public key format from {username_}: {e}")
        response = {"type": "status", "status": "error", "message": "Invalid public key format."}
        await send_response(ws, response)
        return

    if fingerprint_ in online_users:
        logging.warning(f"Fingerprint {fingerprint_.hex()} already online.")
        response = {"type": "status", "status": "error", "message": "User already online."}
        await send_response(ws, response)
        return

    if username_ in username_to_fingerprint:
        logging.warning(f"Username {username_} is already taken.")
        response = {"type": "status", "status": "error", "message": "Username is already taken."}
        await send_response(ws, response)
        return

    if msg_type == "hello":
        # 注册新用户
        online_users[fingerprint_] = ws
        user_public_keys[fingerprint_] = public_key
        fingerprint_to_username[fingerprint_] = username_
        username_to_fingerprint[username_] = fingerprint_
        logging.info(f"User {username_} connected. Online users: {[fp.hex() for fp in online_users.keys()]}")
        response = {"type": "status", "status": "success", "message": "Hello received."}
        await send_response(ws, response)
    elif msg_type == "login":
        # 认证用户（此处简化为直接登录）
        online_users[fingerprint_] = ws
        user_public_keys[fingerprint_] = public_key
        fingerprint_to_username[fingerprint_] = username_
        username_to_fingerprint[username_] = fingerprint_
        logging.info(f"User {username_} logged in successfully. Online users: {[fp.hex() for fp in online_users.keys()]}")
        response = {"type": "status", "status": "success", "message": "Logged in successfully."}
        await send_response(ws, response)

async def handle_list_users(ws, fingerprint):
    users = [fingerprint_to_username[fp] for fp in online_users.keys()]
    response = {"type": "client_list", "servers": users}
    await send_response(ws, response)
    logging.debug(f"Sent client list to {fingerprint_to_username.get(fingerprint, 'Unknown')}.")

async def handle_broadcast(ws, fingerprint, message_body):
    if not message_body:
        logging.warning(f"Broadcast message missing body from {fingerprint_to_username.get(fingerprint, 'Unknown')}.")
        return

    broadcast_message = {
        "type": "broadcast",
        "from": fingerprint_to_username.get(fingerprint, "Unknown"),
        "message": message_body
    }

    # 加密并发送广播消息给所有在线用户，除发送者之外
    for fp, user_ws in online_users.items():
        if fp != fingerprint:
            recipient_public_key = user_public_keys.get(fp)
            if recipient_public_key:
                try:
                    encrypted_payload = encrypt_message(json.dumps(broadcast_message), recipient_public_key)
                    await user_ws.send_str(encrypted_payload)
                    logging.debug(f"Broadcast message sent to {fingerprint_to_username.get(fp, 'Unknown')}.")
                except Exception as e:
                    logging.error(f"Failed to send broadcast message to {fingerprint_to_username.get(fp, 'Unknown')}: {e}")

async def handle_private_message(ws, fingerprint, data):
    recipient_username = data.get("to")
    encrypted_payload = data.get("message")
    counter_ = data.get("counter")

    if not recipient_username or not encrypted_payload or counter_ is None:
        logging.warning(f"Private message from {fingerprint_to_username.get(fingerprint, 'Unknown')} missing fields.")
        response = {"type": "status", "status": "error", "message": "Missing fields in private message."}
        await send_response(ws, response)
        return

    recipient_fingerprint = username_to_fingerprint.get(recipient_username)
    if not recipient_fingerprint:
        logging.warning(f"Private message recipient {recipient_username} not found.")
        response = {"type": "status", "status": "error", "message": f"User {recipient_username} not found."}
        await send_response(ws, response)
        return

    if recipient_fingerprint not in online_users:
        logging.warning(f"Private message recipient {recipient_username} not online.")
        response = {"type": "status", "status": "error", "message": f"User {recipient_username} not online."}
        await send_response(ws, response)
        return

    recipient_ws = online_users[recipient_fingerprint]
    recipient_public_key = user_public_keys.get(recipient_fingerprint)
    if not recipient_public_key:
        logging.warning(f"No public key found for user {recipient_username}.")
        response = {"type": "status", "status": "error", "message": f"No public key found for user {recipient_username}."}
        await send_response(ws, response)
        return

    private_message = {
        "type": "private_message",
        "from": fingerprint_to_username.get(fingerprint, "Unknown"),
        "message": encrypted_payload,
        "counter": counter_
    }

    try:
        encrypted_payload_for_recipient = encrypt_message(json.dumps(private_message), recipient_public_key)
        await recipient_ws.send_str(encrypted_payload_for_recipient)
        logging.debug(f"Private message from {fingerprint_to_username.get(fingerprint, 'Unknown')} sent to {recipient_username}.")
    except Exception as e:
        logging.error(f"Failed to send private message from {fingerprint_to_username.get(fingerprint, 'Unknown')} to {recipient_username}: {e}")
        response = {"type": "status", "status": "error", "message": f"Failed to send message to {recipient_username}."}
        await send_response(ws, response)

async def handle_public_chat(ws, fingerprint, data):
    message = data.get("message")

    if not message:
        logging.warning(f"Public chat message missing 'message' field from {fingerprint_to_username.get(fingerprint, 'Unknown')}.")
        return

    public_chat = {
        "type": "public_chat",
        "sender": fingerprint_to_username.get(fingerprint, "Unknown"),
        "message": message
    }

    # 广播公共聊天消息给所有在线用户，除发送者之外
    for fp, user_ws in online_users.items():
        if fp != fingerprint:
            try:
                await user_ws.send_str(json.dumps(public_chat))
                logging.debug(f"Public chat message from {public_chat['sender']} sent to {fingerprint_to_username.get(fp, 'Unknown')}.")
            except Exception as e:
                logging.error(f"Failed to send public chat to {fingerprint_to_username.get(fp, 'Unknown')}: {e}")

async def handle_group_chat(ws, fingerprint, data):
    destination_servers = data.get("destination_servers")
    symm_keys = data.get("symm_keys")
    encrypted_chat = data.get("chat")

    if not (destination_servers and symm_keys and encrypted_chat):
        logging.warning(f"Group chat message from {fingerprint_to_username.get(fingerprint, 'Unknown')} missing fields.")
        return

    # 确保 destination_servers 和 symm_keys 长度相同
    if len(destination_servers) != len(symm_keys):
        logging.warning(f"Mismatch in destination_servers and symm_keys lengths for group chat from {fingerprint_to_username.get(fingerprint, 'Unknown')}.")
        return

    # 转发加密的聊天消息到指定的邻居服务器
    for server_address, symm_key_b64 in zip(destination_servers, symm_keys):
        symm_key = base64.b64decode(symm_key_b64)
        asyncio.create_task(forward_group_chat(server_address, symm_key, encrypted_chat))

async def forward_group_chat(server_address, symm_key, encrypted_chat):
    try:
        uri = f"ws://{server_address}/neighbour"
        async with websockets.connect(uri) as websocket:
            # 这里可以使用 symm_key 进行额外的加密处理（视需求而定）
            await websocket.send(encrypted_chat)
            logging.debug(f"Forwarded group chat to neighbour server at {server_address}.")
    except Exception as e:
        logging.error(f"Failed to forward group chat to {server_address}: {e}")

async def handle_get_public_key(ws, fingerprint, data):
    target_username = data.get("username")
    if not target_username:
        logging.warning(f"get_public_key request missing 'username' from {fingerprint_to_username.get(fingerprint, 'Unknown')}.")
        response = {"type": "status", "status": "error", "message": "Missing 'username' in get_public_key request."}
        await send_response(ws, response)
        return

    target_fingerprint = username_to_fingerprint.get(target_username)
    if not target_fingerprint:
        logging.warning(f"get_public_key request for unknown user {target_username}.")
        response = {"type": "status", "status": "error", "message": f"User {target_username} not found."}
        await send_response(ws, response)
        return

    target_public_key = user_public_keys.get(target_fingerprint)
    if not target_public_key:
        logging.warning(f"No public key found for user {target_username}.")
        response = {"type": "status", "status": "error", "message": f"No public key found for user {target_username}."}
        await send_response(ws, response)
        return

    target_public_key_pem = target_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    response = {
        "type": "public_key",
        "username": target_username,
        "public_key": target_public_key_pem
    }
    await send_response(ws, response)
    logging.debug(f"Sent public key of {target_username} to {fingerprint_to_username.get(fingerprint, 'Unknown')}.")

async def process_neighbour_message(message_data):
    msg_type = message_data.get("type")
    if msg_type == "client_update":
        clients = message_data.get("clients", [])
        # 根据 client_update 更新内部客户端列表
        logging.debug(f"Received client_update from neighbour: {clients}")
        # 实现实际的更新逻辑
    elif msg_type == "client_update_request":
        # 回复 client_update
        clients = [fingerprint_to_username[fp] for fp in online_users.keys()]
        response = {"type": "client_update", "clients": clients}
        # 加密并发送回复给请求的邻居
        # 这里简化为直接发送明文（可根据需求修改为加密）
        logging.debug("Received client_update_request from neighbour.")
    elif msg_type == "server_hello":
        sender_address = message_data.get("sender")
        logging.debug(f"Received server_hello from {sender_address}.")
        # 处理服务器身份验证
    else:
        logging.warning(f"Unhandled neighbour message type: {msg_type}")

async def send_response(ws, response):
    # 获取接收者的公钥
    fingerprint_ = get_fingerprint_by_websocket(ws)
    if not fingerprint_:
        logging.warning("Attempted to send response to unidentified websocket.")
        return

    recipient_public_key = user_public_keys.get(fingerprint_)
    if not recipient_public_key:
        logging.warning(f"No public key found for fingerprint {fingerprint_.hex()}. Cannot send response.")
        return

    try:
        # 加密响应
        encrypted_response = encrypt_message(json.dumps(response), recipient_public_key)
        await ws.send_str(encrypted_response)
        logging.debug(f"Sent response to {fingerprint_to_username.get(fingerprint_, 'Unknown')}: {response}")
    except Exception as e:
        logging.error(f"Failed to send response to {fingerprint_to_username.get(fingerprint_, 'Unknown')}: {e}")

def get_fingerprint_by_websocket(ws):
    for fp, user_ws in online_users.items():
        if user_ws == ws:
            return fp
    return None

# HTTP 处理器，用于文件上传和下载
async def handle_upload(request):
    reader = await request.multipart()
    field = await reader.next()
    if field.name != 'file':
        return web.Response(status=400, text="Expected 'file' field.")

    filename = field.filename
    file_path = os.path.join(FILE_STORAGE_DIR, filename)

    with open(file_path, 'wb') as f:
        while True:
            chunk = await field.read_chunk()  # 默认 8192 字节
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

async def connect_to_neighbour_servers(neighbour_addresses):
    for server_address in neighbour_addresses:
        asyncio.create_task(connect_to_single_neighbour(server_address))

async def connect_to_single_neighbour(server_address):
    if server_address in connected_neighbours:
        logging.debug(f"Already connected to neighbour server at {server_address}.")
        return

    while True:
        try:
            uri = f"ws://{server_address}/neighbour"
            async with websockets.connect(uri) as websocket:
                # 发送 PSK 进行身份验证
                await websocket.send(server_psk)
                received_psk = await websocket.recv()
                if received_psk != server_psk:
                    logging.error(f"Neighbour server at {server_address} failed PSK authentication.")
                    await websocket.close()
                    await asyncio.sleep(5)
                    continue

                logging.info(f"Authenticated neighbour server at {server_address}.")

                # 接收邻居服务器的公钥
                neighbour_public_key_pem = await websocket.recv()
                neighbour_public_key = serialization.load_pem_public_key(neighbour_public_key_pem.encode('utf-8'))

                connected_neighbours[server_address] = websocket

                # 可选：发送服务器自我介绍
                await websocket.send(json.dumps({
                    "type": "server_hello",
                    "sender": server_address
                }))
                logging.debug(f"Sent server_hello to {server_address}.")

                # 开始监听来自邻居服务器的消息
                asyncio.create_task(handle_neighbour(websocket, server_address))

                # 阻塞，直到连接关闭
                await websocket.wait_closed()
        except Exception as e:
            logging.error(f"Failed to connect to neighbour server at {server_address}: {e}")

        logging.info(f"Retrying connection to neighbour server at {server_address} in 5 seconds...")
        await asyncio.sleep(5)

async def handle_neighbour(websocket, server_address):
    try:
        async for message in websocket:
            try:
                # 假设来自邻居的消息已经是加密的 JSON
                decrypted_json = decrypt_message(message, server_private_key)
                message_data = json.loads(decrypted_json)
                await process_neighbour_message(message_data)
            except Exception as e:
                logging.error(f"Error processing neighbour message from {server_address}: {e}")
    except ConnectionClosed:
        logging.info(f"Connection closed by neighbour server at {server_address}.")
    except Exception as e:
        logging.error(f"Error handling messages from neighbour server at {server_address}: {e}")
    finally:
        if server_address in connected_neighbours:
            del connected_neighbours[server_address]
            logging.info(f"Removed neighbour server at {server_address} from connected neighbours.")

async def main():
    parser = argparse.ArgumentParser(description="Start a chat server.")
    parser.add_argument('--ws_port', type=int, default=8080, help='WebSocket server port')
    parser.add_argument('--http_port', type=int, default=8000, help='HTTP server port')
    parser.add_argument('--neighbours', type=str, nargs='*', default=[], help='List of neighbour server addresses (e.g., localhost:8081)')
    args = parser.parse_args()

    server_ws_port = args.ws_port
    server_http_port = args.http_port
    neighbour_addresses = args.neighbours  # 手动配置的邻居服务器地址列表

    # 启动 WebSocket 服务器和邻居 WebSocket 处理器
    app = web.Application()
    app.router.add_get('/ws', handle_client_websocket)
    app.router.add_get('/neighbour', handle_neighbour_websocket)

    runner = web.AppRunner(app)
    await runner.setup()
    ws_site = web.TCPSite(runner, '0.0.0.0', server_ws_port)
    await ws_site.start()
    logging.info(f"WebSocket server started on ws://0.0.0.0:{server_ws_port}/ws")
    logging.info(f"Neighbour WebSocket handler started on ws://0.0.0.0:{server_ws_port}/neighbour")

    # 启动 HTTP 服务器用于文件传输
    http_app = start_http_server()
    http_runner = web.AppRunner(http_app)
    await http_runner.setup()
    http_site = web.TCPSite(http_runner, '0.0.0.0', server_http_port)
    await http_site.start()
    logging.info(f"HTTP server started on http://0.0.0.0:{server_http_port}")

    # 连接到手动配置的邻居服务器
    await connect_to_neighbour_servers(neighbour_addresses)

    # 处理优雅关闭
    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()

    def shutdown():
        shutdown_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown)

    await shutdown_event.wait()

    # 关闭所有邻居连接
    for addr, ws in connected_neighbours.items():
        await ws.close()
        logging.info(f"Closed connection to neighbour server at {addr}.")

    # 关闭 WebSocket 服务器
    await runner.cleanup()

    # 关闭 HTTP 服务器
    await http_runner.cleanup()

    logging.info("Server shutdown gracefully.")

if __name__ == "__main__":
    asyncio.run(main())
