import json
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def create_message(message_type, data, private_key, counter):
    message = {
        "type": "signed_data",
        "data": {
            "type": message_type,
            **data
        },
        "counter": counter
    }
    
    # If it is a hello message, it needs to contain the public key
    if message_type == "hello":
        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        message["data"]["public_key"] = public_key_pem.decode()

    # Create a signature
    message_bytes = json.dumps(message["data"]).encode() + str(counter).encode()
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    message["signature"] = base64.b64encode(signature).decode()
    
    return json.dumps(message)

def parse_and_verify_message(message_json, public_key):
    message = json.loads(message_json)
    data = message["data"]
    counter = message["counter"]
    signature = base64.b64decode(message["signature"])
    
    # Verify the signature
    message_bytes = json.dumps(data).encode() + str(counter).encode()
    try:
        public_key.verify(
            signature,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except:
        raise ValueError("Invalid signature")
    
    return data, counter