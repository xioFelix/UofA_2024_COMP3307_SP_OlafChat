# common/chat_protocol.py

import json
import base64
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 定义消息类型
MESSAGE_TYPE_HELLO = "hello"
MESSAGE_TYPE_CHAT = "chat"
MESSAGE_TYPE_PUBLIC_CHAT = "public_chat"
MESSAGE_TYPE_CLIENT_LIST_REQUEST = "client_list_request"
MESSAGE_TYPE_CLIENT_LIST = "client_list"
MESSAGE_TYPE_CLIENT_UPDATE = "client_update"
MESSAGE_TYPE_CLIENT_UPDATE_REQUEST = "client_update_request"
MESSAGE_TYPE_SERVER_HELLO = "server_hello"

# 加密和签名相关函数
def generate_rsa_keys():
    """
    生成RSA密钥对。
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """
    序列化公钥为PEM格式。
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_data):
    """
    从PEM格式反序列化公钥。
    """
    return serialization.load_pem_public_key(pem_data)

def sign_message(private_key, message):
    """
    使用私钥对消息进行签名。
    """
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode()

def verify_signature(public_key, message, signature):
    """
    使用公钥验证签名。
    """
    try:
        public_key.verify(
            base64.b64decode(signature),
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

def encrypt_message(symm_key, iv, plaintext):
    """
    使用对称密钥加密消息。
    """
    cipher = Cipher(algorithms.AES(symm_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode()

def decrypt_message(symm_key, iv, ciphertext):
    """
    使用对称密钥解密消息。
    """
    cipher = Cipher(algorithms.AES(symm_key), modes.GCM(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(base64.b64decode(ciphertext)) + decryptor.finalize()
    return plaintext.decode()

def encrypt_symm_key(symm_key, public_key):
    """
    使用接收者的公钥加密对称密钥。
    """
    encrypted_key = public_key.encrypt(
        symm_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_key).decode()

def decrypt_symm_key(encrypted_symm_key, private_key):
    """
    使用私钥解密对称密钥。
    """
    symm_key = private_key.decrypt(
        base64.b64decode(encrypted_symm_key),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return symm_key

def generate_iv():
    """
    生成随机的初始化向量（IV）。
    """
    return base64.b64encode(os.urandom(16)).decode()

def generate_symm_key():
    """
    生成随机的对称密钥。
    """
    return os.urandom(32)
