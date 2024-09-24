# registry.py

import asyncio
from aiohttp import web
import json
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,  # 设置为 INFO 以减少冗余
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# 注册的服务器集合
registered_servers = set()

# 注册新服务器的处理器
async def register_server(request):
    try:
        data = await request.json()
        server_address = data.get("address")
        if not server_address:
            return web.json_response({"status": "error", "message": "Missing 'address' field."}, status=400)
        
        registered_servers.add(server_address)
        logging.info(f"Registered server: {server_address}")
        return web.json_response({"status": "success", "message": f"Registered server {server_address}."})
    except Exception as e:
        logging.error(f"Error registering server: {e}")
        return web.json_response({"status": "error", "message": "Invalid request."}, status=400)

# 注销服务器的处理器
async def deregister_server(request):
    try:
        data = await request.json()
        server_address = data.get("address")
        if not server_address:
            return web.json_response({"status": "error", "message": "Missing 'address' field."}, status=400)
        
        registered_servers.discard(server_address)
        logging.info(f"Deregistered server: {server_address}")
        return web.json_response({"status": "success", "message": f"Deregistered server {server_address}."})
    except Exception as e:
        logging.error(f"Error deregistering server: {e}")
        return web.json_response({"status": "error", "message": "Invalid request."}, status=400)

# 列出所有已注册服务器的处理器
async def list_servers(request):
    return web.json_response({"status": "success", "servers": list(registered_servers)})

def main():
    app = web.Application()
    app.router.add_post('/register', register_server)
    app.router.add_post('/deregister', deregister_server)
    app.router.add_get('/servers', list_servers)
    
    logging.info("Starting Registry Server on http://0.0.0.0:9090")
    web.run_app(app, host='0.0.0.0', port=9090)

if __name__ == "__main__":
    main()
