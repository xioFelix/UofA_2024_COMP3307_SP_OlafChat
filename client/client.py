# client.py

import asyncio
import json
import os
import sys
import base64
import hashlib
import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from aiohttp import ClientSession
import websockets
from websockets.exceptions import ConnectionClosed

# 配置日志
logging.basicConfig(
    level=logging.DEBUG,  # 设置为 DEBUG 以获取详细日志
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# 全局状态
username = None
private_key = None
public_key_pem = None
fingerprint = None
counter = 0
received_user_public_keys = {}  # username -> public_key (RSA public key object)

# HTTP URI，用于文件上传与下载
http_uri = None

# 加载或生成客户端的 RSA 密钥对
def load_or_generate_client_keys(username):
    private_key_file = f"{username}_private_key.pem"
    public_key_file = f"{username}_public_key.pem"

    if os.path.exists(private_key_file) and os.path.exists(public_key_file):
        with open(private_key_file, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        with open(public_key_file, "rb") as key_file:
            public_key_pem = key_file.read().decode('utf-8')
        logging.info(f"Loaded existing keys for user {username}.")
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        with open(private_key_file, "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
        with open(public_key_file, "wb") as key_file:
            key_file.write(public_key_pem.encode('utf-8'))
        logging.info(f"Generated new keys for user {username}.")

    return private_key, public_key_pem

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
    使用接收者的私钥和 AES-GCM 对称解密解密接收到的消息。
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

async def connect_to_server(uri):
    try:
        websocket = await websockets.connect(uri)
        logging.info(f"Connected to server at {uri}")
        return websocket
    except Exception as e:
        logging.error(f"Failed to connect to server at {uri}: {e}")
        return None

async def receive_messages(websocket):
    try:
        async for message in websocket:
            try:
                decrypted_json = decrypt_message(message, private_key)
                data = json.loads(decrypted_json)

                msg_type = data.get("type")

                if msg_type == "status":
                    status = data.get("status")
                    msg = data.get("message")
                    print(f"{status.upper()}: {msg}")
                elif msg_type == "client_list":
                    users = data.get("servers")
                    print(f"Online users: {users}")
                elif msg_type == "broadcast":
                    sender = data.get("from")
                    msg = data.get("message")
                    print(f"[Broadcast] {sender}: {msg}")
                elif msg_type == "public_chat":
                    sender = data.get("sender")
                    msg = data.get("message")
                    print(f"[Public Chat] {sender}: {msg}")
                elif msg_type == "private_message":
                    sender = data.get("from")
                    encrypted_payload = data.get("message")
                    decrypted_message = decrypt_message(encrypted_payload, private_key)
                    print(f"[Private] {sender}: {decrypted_message}")
                elif msg_type == "public_key":
                    target_username = data.get("username")
                    public_key_pem_received = data.get("public_key")
                    if target_username and public_key_pem_received:
                        try:
                            public_key = serialization.load_pem_public_key(public_key_pem_received.encode('utf-8'))
                            received_user_public_keys[target_username] = public_key
                            print(f"Received public key for {target_username}.")
                            logging.debug(f"Received public key for {target_username}.")
                        except Exception as e:
                            logging.error(f"Failed to load public key for {target_username}: {e}")
                    else:
                        logging.warning(f"Received malformed public key response: {data}")
                else:
                    logging.warning(f"Unhandled message type: {msg_type}")
            except Exception as e:
                logging.error(f"Error processing received message: {e}")
    except ConnectionClosed:
        logging.info("Connection closed by server.")
    except Exception as e:
        logging.error(f"Error receiving messages: {e}")

async def send_hello(websocket, mode):
    global counter
    counter += 1
    message = {
        "type": mode,  # 'hello' 或 'login'
        "username": username,
        "public_key": public_key_pem
    }
    signed_data = {
        "type": "signed_data",
        "data": message,
        "counter": counter,
        "signature": sign_message(private_key, json.dumps(message) + str(counter))
    }
    encrypted_message = encrypt_message(json.dumps(signed_data), await get_server_public_key(websocket))
    await websocket.send(encrypted_message)

async def get_server_public_key(websocket):
    # 假设服务器在连接后发送其公钥
    server_public_key_pem_received = await websocket.recv()
    server_public_key = serialization.load_pem_public_key(server_public_key_pem_received.encode('utf-8'))
    return server_public_key

async def user_input_loop(websocket):
    loop = asyncio.get_event_loop()
    while True:
        try:
            user_input = await loop.run_in_executor(None, sys.stdin.readline)
            if not user_input:
                continue
            user_input = user_input.strip()
            if user_input.startswith("/"):
                await handle_command(user_input, websocket)
            else:
                print("Invalid command. Type /help for available commands.")
        except Exception as e:
            logging.error(f"Error in user input loop: {e}")

async def handle_command(command, websocket):
    global counter
    if command.startswith("/list"):
        counter += 1
        message = {
            "type": "list_users"
        }
        signed_data = {
            "type": "signed_data",
            "data": message,
            "counter": counter,
            "signature": sign_message(private_key, json.dumps(message) + str(counter))
        }
        encrypted_message = encrypt_message(json.dumps(signed_data), await get_server_public_key(websocket))
        await websocket.send(encrypted_message)
    elif command.startswith("/broadcast "):
        message_body = command[len("/broadcast "):]
        counter += 1
        message = {
            "type": "broadcast",
            "body": message_body
        }
        signed_data = {
            "type": "signed_data",
            "data": message,
            "counter": counter,
            "signature": sign_message(private_key, json.dumps(message) + str(counter))
        }
        encrypted_message = encrypt_message(json.dumps(signed_data), await get_server_public_key(websocket))
        await websocket.send(encrypted_message)
    elif command.startswith("/msg "):
        parts = command.split(" ", 2)
        if len(parts) < 3:
            print("Usage: /msg <username> <message>")
            return
        recipient, message_body = parts[1], parts[2]
        counter += 1
        recipient_public_key = received_user_public_keys.get(recipient)
        if not recipient_public_key:
            print(f"Public key for user {recipient} not found. Use /get_public_key {recipient} to retrieve it.")
            return
        message = {
            "type": "private_message",
            "to": recipient,
            "message": message_body,
            "counter": counter
        }
        signed_data = {
            "type": "signed_data",
            "data": message,
            "counter": counter,
            "signature": sign_message(private_key, json.dumps(message) + str(counter))
        }
        encrypted_message = encrypt_message(json.dumps(signed_data), recipient_public_key)
        await websocket.send(encrypted_message)
    elif command.startswith("/public "):
        message_body = command[len("/public "):]
        counter += 1
        message = {
            "type": "public_chat",
            "message": message_body
        }
        signed_data = {
            "type": "signed_data",
            "data": message,
            "counter": counter,
            "signature": sign_message(private_key, json.dumps(message) + str(counter))
        }
        encrypted_message = encrypt_message(json.dumps(signed_data), await get_server_public_key(websocket))
        await websocket.send(encrypted_message)
    elif command.startswith("/upload "):
        filepath = command[len("/upload "):]
        await upload_file(filepath)
    elif command.startswith("/download "):
        file_url = command[len("/download "):]
        await download_file(file_url)
    elif command.startswith("/get_public_key "):
        target_username = command[len("/get_public_key "):]
        counter += 1
        message = {
            "type": "get_public_key",
            "username": target_username
        }
        signed_data = {
            "type": "signed_data",
            "data": message,
            "counter": counter,
            "signature": sign_message(private_key, json.dumps(message) + str(counter))
        }
        encrypted_message = encrypt_message(json.dumps(signed_data), await get_server_public_key(websocket))
        await websocket.send(encrypted_message)
    elif command.startswith("/help"):
        show_help()
    elif command.startswith("/quit"):
        print("Exiting...")
        await websocket.close()
        sys.exit(0)
    else:
        print("Unknown command. Type /help for available commands.")

async def upload_file(filepath):
    if not os.path.exists(filepath):
        print(f"File {filepath} does not exist.")
        return

    filename = os.path.basename(filepath)
    url = f"{http_uri}/api/upload"

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

async def download_file(file_url):
    async with ClientSession() as session:
        try:
            async with session.get(file_url) as resp:
                if resp.status == 200:
                    filename = os.path.basename(file_url)
                    directory = f"{username}_downloads"
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

def show_help():
    help_text = """
Available commands:
    /list                         - Show online users.
    /broadcast <message>          - Send a broadcast message.
    /msg <username> <message>     - Send a private message to a user.
    /public <message>             - Send a public chat message.
    /upload <filepath>            - Upload a file to the server.
    /download <file_url>          - Download a file from the server.
    /get_public_key <username>    - Retrieve the public key of a user.
    /help                         - Show this help message.
    /quit                         - Exit the chat.
    """
    print(help_text)
    logging.debug("Displayed help information.")

async def main():
    global username, private_key, public_key_pem, fingerprint, counter, http_uri

    if len(sys.argv) != 3:
        print("Usage: python3 client.py <server_ws_uri> <server_http_uri>")
        print("Example: python3 client.py ws://localhost:8080/ws http://localhost:8000")
        sys.exit(1)

    server_ws_uri = sys.argv[1]
    server_http_uri = sys.argv[2]
    http_uri = server_http_uri  # 用于文件上传与下载

    # 输入用户名
    username = input("Enter username: ").strip()
    if not username:
        print("Username cannot be empty.")
        sys.exit(1)

    # 加载或生成密钥
    private_key, public_key_pem = load_or_generate_client_keys(username)
    public_key = private_key.public_key()
    fingerprint = compute_fingerprint(public_key)

    # 连接到服务器
    websocket = await connect_to_server(server_ws_uri)
    if not websocket:
        print("Failed to connect to the server.")
        sys.exit(1)

    # 接收服务器的公钥
    server_public_key_pem_received = await websocket.recv()
    server_public_key = serialization.load_pem_public_key(server_public_key_pem_received.encode('utf-8'))

    # 发送 hello 消息
    mode = "hello"  # 或 "login" 根据需求
    await send_hello(websocket, mode)

    # 启动接收消息任务
    asyncio.create_task(receive_messages(websocket))

    # 启动用户输入循环
    await user_input_loop(websocket)

if __name__ == "__main__":
    asyncio.run(main())
