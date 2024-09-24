from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from backend.security.encryption import generate_rsa_keys, sign_message, verify_signature
import json
from cryptography.hazmat.primitives import serialization

app = FastAPI()

# Enable CORS to allow frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for testing; restrict in production
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

# In-memory databases for storing users and connections
users_db = {}  # Stores users' public and private keys
connections_db = {}  # Stores active WebSocket connections

class ConnectionManager:
    def __init__(self):
        self.active_connections = {}

    async def connect(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.active_connections[client_id] = websocket
        print(f"Client {client_id} connected")

    def disconnect(self, client_id: str):
        self.active_connections.pop(client_id, None)
        print(f"Client {client_id} disconnected")

    async def send_private_message(self, message: str, recipient_id: str):
        if recipient_id in self.active_connections:
            await self.active_connections[recipient_id].send_text(message)
        else:
            print(f"Recipient {recipient_id} not connected")

    async def broadcast(self, message: str):
        for connection in self.active_connections.values():
            await connection.send_text(message)

manager = ConnectionManager()

# Registration endpoint
@app.post("/register")
async def register(username: str):
    if username in users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    
    private_key, public_key = generate_rsa_keys()
    
    # Store the keys in the users database
    users_db[username] = {
        "private_key": private_key,
        "public_key": public_key
    }
    
    # Return the public key to the client in PEM format
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {"public_key": pem.decode('utf-8')}

# Login endpoint
@app.post("/login")
async def login(username: str):
    if username not in users_db:
        raise HTTPException(status_code=400, detail="User does not exist")
    
    public_key = users_db[username]["public_key"]
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {"public_key": pem.decode('utf-8')}

@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    await manager.connect(websocket, client_id)
    try:
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)

            # Verify the signature of the sender
            sender_id = message_data['sender']
            signature = message_data['signature']
            if not verify_signature(users_db[sender_id]['public_key'], message_data['message'], signature):
                print("Invalid signature, discarding message")
                continue

            # Handle private and broadcast messages
            if message_data['type'] == 'private':
                recipient_id = message_data['recipient']
                await manager.send_private_message(message_data['message'], recipient_id)

            elif message_data['type'] == 'broadcast':
                await manager.broadcast(message_data['message'])

    except WebSocketDisconnect:
        manager.disconnect(client_id)
