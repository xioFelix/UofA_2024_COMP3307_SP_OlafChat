import sys
import os
import asyncio
import websockets
import json
from utils import load_or_generate_keys
from common.chat_protocol import (
    MESSAGE_TYPE_HELLO,
    MESSAGE_TYPE_CHAT,
    MESSAGE_TYPE_PUBLIC_CHAT,
    MESSAGE_TYPE_CLIENT_LIST_REQUEST,
    MESSAGE_TYPE_CLIENT_LIST,
    sign_message,
    encrypt_message,
    encrypt_symm_key,
    serialize_public_key,
    generate_iv,
    generate_symm_key
)
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization
import aiohttp
import logging
import base64
from common import config

# 设置日志级别为 DEBUG 以捕获更多信息
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s:%(message)s')

# 后门token
BACKDOOR_TOKEN = "secret_token"

# 客户端密钥路径
PRIVATE_KEY_PATH = "client/keys/client_private_key.pem"
PUBLIC_KEY_PATH = "client/keys/client_public_key.pem"

class Client:
    def __init__(self, server_address, server_port, http_port, name):
        self.server_address = server_address
        self.server_port = server_port
        self.http_port = http_port
        self.name = name  # 用户名
        self.private_key, self.public_key = load_or_generate_keys(
            PRIVATE_KEY_PATH, PUBLIC_KEY_PATH
        )
        self.counter = 0

    async def connect(self, use_backdoor=False):
        uri = f"ws://{self.server_address}:{self.server_port}"
        try:
            logging.debug(f"尝试连接到 WebSocket 服务器: {uri}")
            async with websockets.connect(uri) as websocket:
                logging.info(f"已连接到 WebSocket 服务器: {uri}")
                await self.send_hello(websocket, use_backdoor)
                # 启动两个任务：监听服务器消息和发送用户消息
                listener_task = asyncio.create_task(self.listen(websocket))
                sender_task = asyncio.create_task(self.send_messages(websocket))
                await asyncio.gather(listener_task, sender_task)
        except Exception as e:
            logging.error(f"连接服务器时出错: {e}")

    async def send_hello(self, websocket, use_backdoor=False):
        self.counter += 1
        hello_message = {
            "data": {
                "type": MESSAGE_TYPE_HELLO,
                "public_key": serialize_public_key(self.public_key).decode(),
                "name": self.name  # 添加用户名
            },
            "counter": self.counter,
            "signature": ""
        }
        if use_backdoor:
            hello_message["data"]["backdoor_token"] = BACKDOOR_TOKEN
        # 签名
        message_bytes = json.dumps(hello_message["data"]).encode() + str(self.counter).encode()
        hello_message["signature"] = sign_message(self.private_key, message_bytes)
        await websocket.send(json.dumps(hello_message))
        logging.debug(f"发送 Hello 消息: {hello_message}")

    async def listen(self, websocket):
        logging.debug("开始监听服务器消息。")
        async for message in websocket:
            try:
                # 打印原始消息用于调试
                logging.debug(f"接收到的原始消息: {message}")

                message = json.loads(message)
                msg_type = message.get("type")
                if msg_type == MESSAGE_TYPE_CLIENT_LIST:
                    # 假设服务器返回的client list包含用户名
                    servers = message.get("servers", [])
                    if not servers:
                        logging.info("没有服务器信息。")
                        continue
                    clients = servers[0].get("clients", [])
                    if not clients:
                        logging.info("当前没有在线用户。")
                        continue
                    logging.info("当前在线用户列表：")
                    for client in clients:
                        name = client.get("name", "未知")
                        public_key = client.get("public_key", "")
                        logging.info(f" - {name} ({public_key})")
                elif msg_type == MESSAGE_TYPE_CHAT:
                    sender = message["data"].get("sender", "未知")
                    chat = message["data"].get("chat", "")
                    logging.info(f"接收到私信消息 from {sender}: {chat}")
                elif msg_type == MESSAGE_TYPE_PUBLIC_CHAT:
                    sender = message["data"].get("sender", "未知")
                    message_text = message["data"].get("message", "")
                    logging.info(f"接收到群聊消息 from {sender}: {message_text}")
                else:
                    logging.warning(f"未知的消息类型: {msg_type}")
            except json.JSONDecodeError:
                logging.error("接收到的消息不是有效的 JSON 格式。")
            except Exception as e:
                logging.error(f"处理消息时出错: {e}")
        logging.debug("监听任务结束。")

    async def send_chat_message(self, websocket, destination_servers, participants, message_text):
        self.counter += 1
        symm_key = generate_symm_key()
        iv = base64.b64decode(generate_iv())
        encrypted_message = encrypt_message(symm_key, iv, message_text)
        encrypted_symm_keys = [
            encrypt_symm_key(symm_key, load_pem_public_key(pub_key.encode()))
            for pub_key in participants
        ]

        chat_message = {
            "data": {
                "type": MESSAGE_TYPE_CHAT,
                "sender": self.name,  # 添加发送者用户名
                "destination_servers": destination_servers,
                "iv": generate_iv(),
                "symm_keys": encrypted_symm_keys,
                "chat": encrypted_message,
                "participants": participants  # 添加参与者列表
            },
            "counter": self.counter,
            "signature": ""
        }
        # 签名
        message_bytes = json.dumps(chat_message["data"]).encode() + str(self.counter).encode()
        chat_message["signature"] = sign_message(self.private_key, message_bytes)
        await websocket.send(json.dumps(chat_message))
        logging.debug(f"发送私信消息: {chat_message}")
        logging.info("已发送私信消息。")

    async def send_public_chat_message(self, websocket, message_text):
        self.counter += 1
        public_chat_message = {
            "data": {
                "type": MESSAGE_TYPE_PUBLIC_CHAT,
                "sender": self.name,  # 发送者用户名
                "message": message_text
            },
            "counter": self.counter,
            "signature": ""
        }
        # 签名
        message_bytes = json.dumps(public_chat_message["data"]).encode() + str(self.counter).encode()
        public_chat_message["signature"] = sign_message(self.private_key, message_bytes)
        await websocket.send(json.dumps(public_chat_message))
        logging.debug(f"发送群聊消息: {public_chat_message}")
        logging.info("已发送群聊消息。")

    async def request_client_list(self, websocket):
        self.counter += 1
        client_list_request = {
            "data": {
                "type": MESSAGE_TYPE_CLIENT_LIST_REQUEST
            },
            "counter": self.counter,
            "signature": ""
        }
        # 签名
        message_bytes = json.dumps(client_list_request["data"]).encode() + str(self.counter).encode()
        client_list_request["signature"] = sign_message(self.private_key, message_bytes)
        await websocket.send(json.dumps(client_list_request))
        logging.debug(f"请求在线用户列表消息: {client_list_request}")
        logging.info("已请求在线用户列表。")

    async def upload_file(self, file_path):
        url = f"http://{self.server_address}:{self.http_port}/api/upload"
        async with aiohttp.ClientSession() as session:
            try:
                with open(file_path, 'rb') as f:
                    data = aiohttp.FormData()
                    data.add_field('file', f, filename=os.path.basename(file_path))
                    async with session.post(url, data=data) as resp:
                        if resp.status == 200:
                            json_resp = await resp.json()
                            logging.debug(f"上传文件响应: {json_resp}")
                            logging.info(f"文件上传成功。URL: {json_resp['file_url']}")
                            return json_resp["file_url"]
                        else:
                            logging.error(f"文件上传失败。状态码: {resp.status}")
                            return None
            except FileNotFoundError:
                logging.error("指定的文件不存在。")
                return None
            except Exception as e:
                logging.error(f"上传文件时出错: {e}")
                return None

    async def download_file(self, file_url, save_path):
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(file_url) as resp:
                    if resp.status == 200:
                        with open(save_path, 'wb') as f:
                            while True:
                                chunk = await resp.content.read(1024)
                                if not chunk:
                                    break
                                f.write(chunk)
                        logging.debug(f"下载文件响应状态: {resp.status}")
                        logging.info(f"文件已下载到: {save_path}")
                    else:
                        logging.error(f"文件下载失败。状态码: {resp.status}")
            except Exception as e:
                logging.error(f"下载文件时出错: {e}")

    async def send_messages(self, websocket):
        """
        处理用户输入并发送消息。
        """
        while True:
            print("\n选择操作:")
            print("1. 请求在线用户列表")
            print("2. 发送私信")
            print("3. 发送群消息")
            print("4. 上传文件")
            print("5. 下载文件")
            print("6. 退出")
            choice = input("输入选择编号: ")

            if choice == "1":
                await self.request_client_list(websocket)
            elif choice == "2":
                destination_servers = input("输入目标服务器地址（用逗号分隔）: ").split(",")
                participants = input("输入参与者的公钥（用逗号分隔）: ").split(",")
                message_text = input("输入私信内容: ")
                await self.send_chat_message(websocket, destination_servers, participants, message_text)
            elif choice == "3":
                participants = input("输入参与者的公钥（用逗号分隔）: ").split(",")
                message_text = input("输入群消息内容: ")
                await self.send_public_chat_message(websocket, message_text)
            elif choice == "4":
                file_path = input("输入要上传的文件路径: ")
                await self.upload_file(file_path)
            elif choice == "5":
                file_url = input("输入要下载的文件URL: ")
                save_path = input("输入保存文件的路径: ")
                await self.download_file(file_url, save_path)
            elif choice == "6":
                print("退出客户端。")
                await websocket.close()
                break
            else:
                print("无效的选择，请重新输入。")

if __name__ == "__main__":
    # 获取配置
    SERVER_ADDRESS = config.SERVER_ADDRESS
    SERVER_PORT = config.SERVER_PORT
    HTTP_SERVER_PORT = config.HTTP_SERVER_PORT

    # 询问用户输入用户名
    user_name = input("请输入您的用户名: ").strip()
    if not user_name:
        print("用户名不能为空。")
        sys.exit(1)

    # 创建客户端实例
    client = Client(SERVER_ADDRESS, SERVER_PORT, HTTP_SERVER_PORT, name=user_name)

    # 询问是否使用后门连接
    use_backdoor_input = input("是否使用后门连接？（y/n）: ").strip().lower()
    use_backdoor = use_backdoor_input == 'y'

    # 运行客户端
    try:
        asyncio.run(client.connect(use_backdoor=use_backdoor))
    except KeyboardInterrupt:
        print("\n客户端已关闭。")
