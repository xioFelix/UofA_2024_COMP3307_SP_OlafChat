import socket
import os
import json
import logging
import threading
from shared.encryption import (
    load_or_generate_private_key,
    load_public_key,
    serialize_public_key,
    encrypt_message,
    sign_message,
)
from getpass import getpass

logging.basicConfig(level=logging.INFO)


class Client:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.socket = None
        self.private_key = None
        self.server_public_key = None
        self.username = None
        self.logged_in = False

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.server_ip, self.server_port))
        logging.info(f"Connected to server at {self.server_ip}:{self.server_port}")

        # 接收服务器公钥
        server_public_key_pem = self.socket.recv(8192)
        self.server_public_key = load_public_key(server_public_key_pem)
        logging.info("Received server public key.")

    def register_or_login(self):
        self.username = input("Enter your username: ")

        # 根据用户名指定私钥文件名
        key_filename = f"{self.username}_private_key.pem"
        self.private_key = load_or_generate_private_key(key_filename)

        choice = input("Do you want to (r)egister or (l)ogin? ")
        if choice.lower() == "r":
            message = {
                "type": "register",
                "username": self.username,
                "public_key": serialize_public_key(
                    self.private_key.public_key()
                ).decode("utf-8"),
            }
        elif choice.lower() == "l":
            message = {
                "type": "login",
                "username": self.username,
                "public_key": serialize_public_key(
                    self.private_key.public_key()
                ).decode("utf-8"),
            }
        else:
            print("Invalid choice.")
            self.socket.close()
            return False

        self.socket.sendall(json.dumps(message).encode("utf-8"))
        response_data = self.socket.recv(8192)
        response = json.loads(response_data.decode("utf-8"))
        if response["status"] == "success":
            self.logged_in = True
            print(response["message"])
            return True
        else:
            print(response["message"])
            self.socket.close()
            return False

    def send_message(self, content):
        # 签名消息
        signature = sign_message(self.private_key, content)
        message = {"content": content, "signature": signature}
        message_json = json.dumps(message)

        # 加密消息
        encrypted_message = encrypt_message(message_json, self.server_public_key)
        self.socket.sendall(encrypted_message.encode("utf-8"))

    def receive_messages(self):
        while self.logged_in:
            try:
                data = self.socket.recv(8192)
                if not data:
                    break
                response = json.loads(data.decode("utf-8"))
                msg_type = response.get("type")
                if msg_type == "user_list":
                    users = response.get("users")
                    print(f"Online users: {users}")
                elif msg_type == "broadcast":
                    sender = response.get("from")
                    message = response.get("message")
                    print(f"[Broadcast] {sender}: {message}")
                else:
                    print(f"Server response: {response}")
            except Exception as e:
                logging.error(f"Error receiving message: {e}")
                break

    def start(self):
        self.connect()
        if not self.register_or_login():
            return

        # 启动接收消息的线程
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.start()

        try:
            while self.logged_in:
                message = input(
                    "Enter message ('/list' to show online users, '/all <message>' for broadcast, 'quit' to exit): "
                )
                if message.lower() == "quit":
                    self.logged_in = False
                    self.socket.close()
                    break
                elif message.lower() == "/list":
                    # 请求在线用户列表
                    content_data = {"type": "list_users"}
                    content = json.dumps(content_data)
                    self.send_message(content)
                elif message.startswith("/all "):
                    # 发送群聊消息
                    message_body = message[5:]
                    content_data = {"type": "broadcast", "body": message_body}
                    content = json.dumps(content_data)
                    self.send_message(content)
                else:
                    # 发送普通消息（可以扩展为私信功能）
                    print("Unknown command or message format.")
        except KeyboardInterrupt:
            self.logged_in = False
            self.socket.close()
        finally:
            receive_thread.join()
            logging.info("Client shutdown.")


if __name__ == "__main__":
    client = Client("127.0.0.1", 8080)
    client.start()
