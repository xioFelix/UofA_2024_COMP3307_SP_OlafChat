# server.py

import socket
import threading
import logging
import json
import os
import base64
import time
import ssl
import traceback
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
    compute_fingerprint,
)

# 配置日志记录
logging.basicConfig(level=logging.DEBUG)

# 全局变量
online_users = {}  # {fingerprint: {'username': username, 'public_key': public_key_pem}}
client_handlers = {}  # {fingerprint: ClientHandler instance}


class Server:
    """
    处理客户端连接并与邻居服务器通信的主服务器类。
    """

    def __init__(self, host="0.0.0.0", port=8080):
        self.server_private_key = load_or_generate_private_key("server_private_key.pem")
        self.server_public_key_pem = serialize_public_key(
            self.server_private_key.public_key()
        ).decode("utf-8")
        self.host = host
        self.port = port
        self.server_socket = None
        self.lock = threading.Lock()

        self.neighbour_servers = {}  # {address: socket}
        self.neighbour_addresses = set()  # 邻居服务器地址的集合

        # 服务端 SSL 上下文（用于接受连接）
        self.server_ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        # 确保存在 server.crt 和 server.key
        self.server_ssl_context.load_cert_chain(certfile='server.crt', keyfile='server.key')
        self.server_ssl_context.verify_mode = ssl.CERT_NONE  # 不需要客户端证书

        # 客户端 SSL 上下文（用于连接邻居服务器）
        self.client_ssl_context = ssl._create_unverified_context()

        # 用于邻居发现的 UDP 广播配置
        self.broadcast_port = 37020  # 广播端口
        self.discovery_interval = 5  # 发送发现消息的间隔（秒）
        self.discovery_thread = threading.Thread(target=self.discovery_neighbours, daemon=True)
        self.discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.discovery_socket.bind(('', self.broadcast_port))

    def start(self):
        """
        启动服务器，接受客户端连接，并启动邻居发现。
        """
        # 创建 TCP 套接字
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        sock.listen(5)
        logging.info(f"Server started and listening on {self.host}:{self.port}")

        # 使用服务器 SSL 上下文包装套接字
        self.server_socket = self.server_ssl_context.wrap_socket(sock, server_side=True)

        # 启动邻居发现线程
        self.discovery_thread.start()

        try:
            while True:
                client_socket, address = self.server_socket.accept()
                handler = ClientHandler(client_socket, address, self)
                handler.start()
        except KeyboardInterrupt:
            logging.info("Server shutting down.")
        finally:
            self.server_socket.close()

    def discovery_neighbours(self):
        """
        定期广播存在并监听其他服务器。
        """
        threading.Thread(target=self.listen_for_broadcasts, daemon=True).start()

        while True:
            # 构建包含服务器主机和端口的广播消息
            message = json.dumps({
                "type": "server_discovery",
                "host": self.host,
                "port": self.port,
            }).encode('utf-8')

            # 发送广播消息
            self.discovery_socket.sendto(message, ('<broadcast>', self.broadcast_port))
            logging.debug("Broadcasted server discovery message.")

            # 等待指定的间隔
            time.sleep(self.discovery_interval)

    def listen_for_broadcasts(self):
        """
        监听来自其他服务器的广播消息。
        """
        while True:
            try:
                data, addr = self.discovery_socket.recvfrom(1024)
                message = json.loads(data.decode('utf-8'))

                if message.get("type") == "server_discovery":
                    host = message.get("host")
                    port = message.get("port")
                    server_address = f"{host}:{port}"

                    if server_address != f"{self.host}:{self.port}" and server_address not in self.neighbour_addresses:
                        self.neighbour_addresses.add(server_address)
                        self.connect_to_neighbour(host, port)
            except Exception as e:
                logging.error(f"Error in listening for broadcasts: {e}")
                traceback.print_exc()

    def connect_to_neighbour(self, host, port):
        """
        连接到邻居服务器。
        """
        try:
            sock = socket.create_connection((host, int(port)))
            # 使用客户端 SSL 上下文包装套接字
            neighbour_socket = self.client_ssl_context.wrap_socket(sock, server_hostname=host)

            # 发送 server_hello 消息
            data = {
                "type": "server_hello",
                "sender": f"{self.host}:{self.port}",
            }
            message = {
                "data": data,
            }
            message_json = json.dumps(message, separators=(',', ':'), sort_keys=True)
            neighbour_socket.sendall(message_json.encode("utf-8"))

            # 保存邻居服务器的套接字
            neighbour_address = f"{host}:{port}"
            self.neighbour_servers[neighbour_address] = neighbour_socket
            logging.info(f"Connected to neighbour server at {neighbour_address}")

            # 启动线程监听邻居服务器的消息
            threading.Thread(target=self.listen_to_neighbour, args=(neighbour_socket, neighbour_address), daemon=True).start()

            # 发送 client_update_request 消息请求客户端列表
            self.send_client_update_request(neighbour_socket)
        except Exception as e:
            logging.error(f"Failed to connect to neighbour server {host}:{port}: {e}")
            traceback.print_exc()

    def listen_to_neighbour(self, sock, address):
        """
        监听来自邻居服务器的消息。
        """
        try:
            while True:
                data = sock.recv(8192)
                if not data:
                    break
                message = json.loads(data.decode('utf-8'))
                data = message.get("data")
                msg_type = data.get("type")

                if msg_type == "client_update":
                    self.handle_client_update(data)
                elif msg_type == "client_update_request":
                    self.send_client_update(sock)
                elif msg_type == "chat":
                    self.forward_chat_message(data)
                else:
                    logging.warning(f"Unknown message type from neighbour {address}: {msg_type}")
        except Exception as e:
            logging.error(f"Error listening to neighbour {address}: {e}")
            traceback.print_exc()
        finally:
            sock.close()
            self.neighbour_servers.pop(address, None)
            self.neighbour_addresses.discard(address)
            logging.info(f"Disconnected from neighbour {address}")

    def send_client_update_request(self, sock):
        """
        发送 client_update_request 消息到邻居服务器。
        """
        data = {
            "type": "client_update_request"
        }
        message = {
            "data": data,
        }
        message_json = json.dumps(message, separators=(',', ':'), sort_keys=True)
        try:
            sock.sendall(message_json.encode("utf-8"))
            logging.debug("Sent client_update_request to neighbour server.")
        except Exception as e:
            logging.error(f"Failed to send client_update_request: {e}")
            traceback.print_exc()

    def send_client_update(self, sock):
        """
        发送 client_update 消息到邻居服务器。
        """
        with self.lock:
            clients = [
                {
                    "public_key": user_info["public_key"],
                    "username": user_info["username"],
                } for user_info in online_users.values()
            ]
        data = {
            "type": "client_update",
            "clients": clients,
        }
        message = {
            "data": data,
        }
        message_json = json.dumps(message, separators=(',', ':'), sort_keys=True)
        try:
            sock.sendall(message_json.encode("utf-8"))
            logging.debug("Sent client_update to neighbour server.")
        except Exception as e:
            logging.error(f"Failed to send client_update: {e}")
            traceback.print_exc()

    def handle_client_update(self, data):
        """
        处理来自邻居服务器的 client_update 消息。
        """
        clients = data.get("clients")
        # 将这些客户端添加到全局在线用户列表
        with self.lock:
            for client_info in clients:
                client_public_key_pem = client_info["public_key"]
                username = client_info.get("username", "Unknown")
                fingerprint = compute_fingerprint(client_public_key_pem.encode("utf-8"))
                if fingerprint not in online_users:
                    online_users[fingerprint] = {
                        "username": username,  # 对于来自其他服务器的用户，用户名可能不可用
                        "public_key": client_public_key_pem,
                    }
            logging.debug(f"Updated online users from neighbour server: {list(online_users.keys())}")

    def broadcast_client_update(self):
        """
        向所有邻居服务器发送 client_update 消息。
        """
        with self.lock:
            clients = [
                {
                    "public_key": user_info["public_key"],
                    "username": user_info["username"],
                } for user_info in online_users.values()
            ]
        data = {
            "type": "client_update",
            "clients": clients,
        }
        message = {
            "data": data,
        }
        message_json = json.dumps(message, separators=(',', ':'), sort_keys=True)
        for addr, sock in self.neighbour_servers.items():
            try:
                sock.sendall(message_json.encode("utf-8"))
                logging.debug(f"Sent client_update to {addr}")
            except Exception as e:
                logging.error(f"Failed to send client_update to {addr}: {e}")
                traceback.print_exc()

    def forward_chat_message(self, data):
        """
        将聊天消息转发到正确的服务器或客户端。
        """
        # 检查目标服务器是否是自己，如果是，则交付给本地客户端
        destination_servers = data.get("destination_servers")
        participants = data.get("participants")

        for idx, server_address in enumerate(destination_servers):
            if server_address == f"{self.host}:{self.port}":
                # 交付给本地客户端
                recipient_fingerprint = participants[idx + 1]  # Participants[0] 是发送者
                recipient_handler = client_handlers.get(recipient_fingerprint)
                if recipient_handler:
                    recipient_handler.send_chat_message(data)
                    logging.info(f"Delivered chat message to local client {recipient_handler.username}")
                else:
                    logging.warning(f"Recipient client {recipient_fingerprint} not found on this server.")
            else:
                # 转发到邻居服务器
                sock = self.neighbour_servers.get(server_address)
                if sock:
                    message = {
                        "data": data,
                    }
                    message_json = json.dumps(message, separators=(',', ':'), sort_keys=True)
                    try:
                        sock.sendall(message_json.encode("utf-8"))
                        logging.debug(f"Forwarded chat message to neighbour server {server_address}")
                    except Exception as e:
                        logging.error(f"Failed to forward chat message to {server_address}: {e}")
                        traceback.print_exc()
                else:
                    logging.warning(f"Neighbour server {server_address} not connected.")


class ClientHandler(threading.Thread):
    """
    处理单个客户端连接。
    """

    def __init__(self, client_socket, address, server):
        threading.Thread.__init__(self)
        self.client_socket = client_socket
        self.address = address
        self.server = server
        self.client_public_key = None
        self.client_public_key_pem = None
        self.username = None
        self.fingerprint = None
        self.logged_in = False
        self.send_counter = 0
        self.lock = threading.Lock()
        self.last_received_counters = {}  # {sender_fingerprint: counter}

    def send_raw_message(self, message_bytes):
        """
        发送带有长度前缀的原始消息给客户端。
        """
        message_length = len(message_bytes)
        with self.lock:
            # 首先发送消息的长度（4字节，大端序）
            self.client_socket.sendall(message_length.to_bytes(4, byteorder='big'))
            # 发送消息本身
            self.client_socket.sendall(message_bytes)

    def recv_message(self):
        # 读取消息长度（4字节）
        raw_msglen = self.recvall(4)
        if not raw_msglen:
            return None
        msglen = int.from_bytes(raw_msglen, byteorder='big')
        # 读取消息数据
        return self.recvall(msglen)

    def recvall(self, n):
        data = b''
        while len(data) < n:
            packet = self.client_socket.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def run(self):
        """
        处理客户端通信。
        """
        try:
            # 发送服务器公钥给客户端
            self.client_socket.sendall(self.server.server_public_key_pem.encode("utf-8"))
            logging.info(f"Sent server public key to client at {self.address}")

            # 接收客户端的 hello 消息
            encrypted_message = self.recv_message()
            if not encrypted_message:
                self.client_socket.close()
                return

            # 使用服务器的私钥解密消息
            message = decrypt_message(encrypted_message.decode('utf-8'), self.server.server_private_key)
            logging.debug(f"Decrypted client hello message: {message}")

            data = message.get("data")
            counter = message.get("counter")
            signature = message.get("signature")

            # 验证签名
            temp_public_key_pem = data.get("public_key")
            temp_public_key = load_public_key(temp_public_key_pem.encode('utf-8'))

            if not verify_data_signature(temp_public_key, data, counter, signature):
                logging.warning("Signature verification failed during handshake.")
                self.client_socket.close()
                return

            # 提取用户名和客户端公钥
            self.client_public_key_pem = data.get("public_key")
            self.client_public_key = temp_public_key  # 已经加载
            self.username = data.get("username")
            self.fingerprint = compute_fingerprint(self.client_public_key_pem.encode("utf-8"))

            # 将客户端添加到在线用户中
            with self.server.lock:
                online_users[self.fingerprint] = {
                    "username": self.username,
                    "public_key": self.client_public_key_pem,
                }
                client_handlers[self.fingerprint] = self

            self.logged_in = True
            logging.info(f"Client {self.username} connected from {self.address}")

            # 向邻居广播客户端更新
            self.server.broadcast_client_update()

            # 主循环接收来自客户端的消息
            while self.logged_in:
                encrypted_message = self.recv_message()
                if not encrypted_message:
                    logging.debug(f"Client {self.username} disconnected.")
                    break

                # 解密消息
                message = decrypt_message(encrypted_message.decode('utf-8'), self.server.server_private_key)
                logging.debug(f"Decrypted message from {self.username}: {message}")
                data = message.get("data")
                counter = message.get("counter")
                signature = message.get("signature")

                # 验证签名
                if not verify_data_signature(self.client_public_key, data, counter, signature):
                    logging.warning(f"Signature verification failed from {self.username}.")
                    continue

                # 检查计数器以防止重放攻击
                last_counter = self.last_received_counters.get(self.fingerprint, 0)
                if counter <= last_counter:
                    logging.warning(f"Replay attack detected from {self.username}. Message discarded.")
                    continue
                else:
                    self.last_received_counters[self.fingerprint] = counter

                msg_type = data.get("type")
                if msg_type == "public_chat":
                    self.handle_public_chat(data)
                elif msg_type == "chat":
                    self.handle_chat(data)
                elif msg_type == "client_list_request":
                    self.handle_client_list_request()
                else:
                    logging.warning(f"Unknown message type from {self.username}: {msg_type}")

        except Exception as e:
            logging.error(f"Error handling client {self.username}: {e}")
            traceback.print_exc()
        finally:
            self.logout()

    def handle_public_chat(self, data):
        """
        处理来自客户端的公共聊天消息。
        """
        message_text = data.get("message")
        logging.info(f"[Public] {self.username}: {message_text}")
        # 广播给所有连接的客户端
        for handler in client_handlers.values():
            if handler != self:
                handler.send_public_chat(self.fingerprint, message_text)

    def handle_chat(self, data):
        """
        处理来自客户端的私人聊天消息。
        """
        logging.debug(f"Handling chat message from {self.username}")
        destination_servers = data.get("destination_servers")
        participants = data.get("participants")

        # 将消息转发到目标服务器
        for idx, server_address in enumerate(destination_servers):
            if server_address == f"{self.server.host}:{self.server.port}":
                # 交付给本地客户端
                recipient_fingerprint = participants[idx + 1]  # Participants[0] 是发送者
                recipient_handler = client_handlers.get(recipient_fingerprint)
                if recipient_handler:
                    recipient_handler.send_chat_message(data)
                    logging.info(f"Delivered chat message to local client {recipient_handler.username}")
                else:
                    logging.warning(f"Recipient client {recipient_fingerprint} not found on this server.")
            else:
                # 转发到邻居服务器
                sock = self.server.neighbour_servers.get(server_address)
                if sock:
                    message = {
                        "data": data,
                    }
                    message_json = json.dumps(message, separators=(',', ':'), sort_keys=True)
                    try:
                        sock.sendall(message_json.encode("utf-8"))
                        logging.debug(f"Forwarded chat message to neighbour server {server_address}")
                    except Exception as e:
                        logging.error(f"Failed to forward chat message to {server_address}: {e}")
                        traceback.print_exc()
                else:
                    logging.warning(f"Neighbour server {server_address} not connected.")

    def handle_client_list_request(self):
        """
        处理来自客户端的客户端列表请求。
        """
        servers = []
        with self.server.lock:
            servers.append({
                "address": f"{self.server.host}:{self.server.port}",
                "clients": [
                    {
                        "public_key": user_info["public_key"],
                        "username": user_info["username"],
                    } for user_info in online_users.values()
                ]
            })
        data = {
            "type": "client_list",
            "servers": servers,
        }
        logging.debug(f"Sending client list to {self.username}: {data}")
        self.send_response(data)
        logging.debug(f"Sent client list to {self.username}")

    def send_chat_message(self, data):
        """
        向此客户端发送聊天消息。
        """
        # 将发送者的指纹添加到数据中以进行签名验证
        data["from"] = data.get("participants")[0]
        self.send_response(data)

    def send_public_chat(self, sender_fingerprint, message_text):
        """
        向此客户端发送公共聊天消息。
        """
        data = {
            "type": "public_chat",
            "sender": sender_fingerprint,
            "message": message_text,
        }
        self.send_response(data)

    def send_response(self, data):
        self.send_counter += 1
        logging.debug(f"Sending message to {self.username} with counter: {self.send_counter}")
        signature = sign_data(self.server.server_private_key, data, self.send_counter)
        message = {
            "data": data,
            "counter": self.send_counter,
            "signature": signature,
        }
        encrypted_message = encrypt_message(message, self.client_public_key)
        self.send_raw_message(encrypted_message.encode("utf-8"))

    def logout(self):
        """
        处理客户端注销。
        """
        with self.server.lock:
            online_users.pop(self.fingerprint, None)
            client_handlers.pop(self.fingerprint, None)
        self.logged_in = False
        self.client_socket.close()
        logging.info(f"Client {self.username} logged out.")
        # 向邻居广播客户端更新
        self.server.broadcast_client_update()


if __name__ == "__main__":
    server = Server(host="0.0.0.0", port=8080)
    server.start()
