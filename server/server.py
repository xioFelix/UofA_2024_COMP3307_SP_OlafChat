import socket
import threading
import logging
import json
from shared.encryption import (
    load_or_generate_private_key,
    load_public_key,
    serialize_public_key,
    decrypt_message,
    verify_signature,
)
from auth import UserManager

logging.basicConfig(level=logging.INFO)

# 全局用户管理器
user_manager = UserManager("user_data.json")

# 全局在线用户集合和客户端连接字典
online_users = set()
client_connections = {}


class ClientHandler(threading.Thread):
    def __init__(self, client_socket, address, server_private_key):
        threading.Thread.__init__(self)
        self.client_socket = client_socket
        self.address = address
        self.server_private_key = server_private_key
        self.client_public_key = None
        self.username = None
        self.logged_in = False

    def run(self):
        try:
            logging.info(f"Handling client {self.address}")

            # 发送服务器的公钥
            server_public_key_pem = serialize_public_key(
                self.server_private_key.public_key()
            )
            self.client_socket.sendall(server_public_key_pem)

            # 接收客户端的公钥和用户名
            data = self.client_socket.recv(8192)
            message = data.decode("utf-8")
            message = json.loads(message)

            if message["type"] == "register":
                self.username = message["username"]
                client_public_key_pem = message["public_key"].encode("utf-8")
                self.client_public_key = load_public_key(client_public_key_pem)

                # 注册用户
                if user_manager.register_user(
                    self.username, client_public_key_pem.decode("utf-8")
                ):
                    self.logged_in = True
                    response = {
                        "status": "success",
                        "message": "Registered successfully.",
                    }
                else:
                    response = {
                        "status": "error",
                        "message": "Username already exists.",
                    }
                    self.send_response(response)
                    self.client_socket.close()
                    return

                self.send_response(response)

            elif message["type"] == "login":
                self.username = message["username"]
                client_public_key_pem = message["public_key"].encode("utf-8")
                self.client_public_key = load_public_key(client_public_key_pem)

                # 验证用户
                stored_public_key_pem = user_manager.get_user_public_key(self.username)
                if (
                    stored_public_key_pem
                    and stored_public_key_pem == client_public_key_pem.decode("utf-8")
                ):
                    self.logged_in = True
                    response = {
                        "status": "success",
                        "message": "Logged in successfully.",
                    }
                else:
                    response = {
                        "status": "error",
                        "message": "Invalid username or key.",
                    }
                    self.send_response(response)
                    self.client_socket.close()
                    return

                self.send_response(response)

            else:
                response = {"status": "error", "message": "Invalid message type."}
                self.send_response(response)
                self.client_socket.close()
                return

            if self.logged_in:
                # 用户成功登录，添加到在线用户列表和连接字典
                online_users.add(self.username)
                client_connections[self.username] = self.client_socket
                logging.info(
                    f"User {self.username} logged in. Online users: {online_users}"
                )

            # 主循环，处理客户端消息
            while self.logged_in:
                data = self.client_socket.recv(8192)
                if not data:
                    break

                message_json = decrypt_message(
                    data.decode("utf-8"), self.server_private_key
                )
                message = json.loads(message_json)

                # 验证签名
                signature = message.get("signature")
                content = message.get("content")
                if not verify_signature(self.client_public_key, content, signature):
                    logging.warning("Signature verification failed.")
                    continue

                # 解析消息内容
                content_data = json.loads(content)

                # 根据消息类型进行处理
                msg_type = content_data.get("type")
                if msg_type == "list_users":
                    self.handle_list_users()
                elif msg_type == "broadcast":
                    self.handle_broadcast(content_data.get("body"))
                else:
                    self.handle_message(content_data)

        except Exception as e:
            logging.error(f"Error handling client {self.address}: {e}")
        finally:
            # 用户断开连接，从在线用户列表中移除
            if self.username in online_users:
                online_users.remove(self.username)
                client_connections.pop(self.username, None)
                logging.info(
                    f"User {self.username} disconnected. Online users: {online_users}"
                )
            self.client_socket.close()
            logging.info(f"Connection with {self.address} closed.")

    def send_response(self, response):
        response_json = json.dumps(response)
        self.client_socket.sendall(response_json.encode("utf-8"))

    def handle_list_users(self):
        user_list = list(online_users)
        response = {"type": "user_list", "users": user_list}
        self.send_response(response)

    def handle_broadcast(self, message_body):
        # 构建广播消息
        broadcast_message = {
            "type": "broadcast",
            "from": self.username,
            "message": message_body,
        }
        message_json = json.dumps(broadcast_message)

        # 向所有在线客户端发送消息
        for username, conn in client_connections.items():
            if username != self.username:
                try:
                    conn.sendall(message_json.encode("utf-8"))
                except Exception as e:
                    logging.error(f"Error sending broadcast to {username}: {e}")

    def handle_message(self, content_data):
        # 处理其他类型的消息
        logging.info(f"Received message from {self.username}: {content_data}")
        response = {"status": "success", "message": "Message received."}
        self.send_response(response)


def start_server(host="0.0.0.0", port=8080):
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
