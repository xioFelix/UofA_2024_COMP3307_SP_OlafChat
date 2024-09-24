# common/utils.py

import os
import hashlib
import logging
from cryptography.hazmat.primitives import serialization
from .chat_protocol import generate_rsa_keys, serialize_public_key

logging.basicConfig(level=logging.INFO)

def load_or_generate_keys(private_key_path, public_key_path):
    """
    加载现有的RSA密钥对，或生成新的密钥对并保存到指定路径。
    """
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        logging.info(f"Loading existing keys from {private_key_path} and {public_key_path}")
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    else:
        logging.info("Generating new RSA key pair")
        private_key, public_key = generate_rsa_keys()
        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(public_key_path, "wb") as f:
            f.write(serialize_public_key(public_key))
        logging.info(f"Keys saved to {private_key_path} and {public_key_path}")
    return private_key, public_key

def generate_fingerprint(public_key):
    """
    基于用户的RSA公钥生成唯一的指纹（SHA-256哈希）。
    """
    public_pem = serialize_public_key(public_key)
    sha256 = hashlib.sha256()
    sha256.update(public_pem)
    fingerprint = sha256.hexdigest()
    return fingerprint
