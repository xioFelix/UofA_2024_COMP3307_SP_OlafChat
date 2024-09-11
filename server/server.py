import socket
import logging
import json
from cryptography.hazmat.primitives import serialization
from protocol.message_format import parse_and_verify_message
from shared.encryption import get_private_key, decrypt_message

# 配置日志
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# 获取私钥
private_key = get_private_key()

def handle_client(client_sock):
    logging.info("Handling new client connection")

    # 获取服务器的公钥
    public_key = private_key.public_key()

    # 将公钥以PEM格式发送给客户端，并记录公钥
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    client_sock.send(public_key_pem)
    logging.info(f"Sent public key to client:\n{public_key_pem.decode('utf-8')}")

    client_public_key = None

    # Receive and process encrypted messages from clients
    while True:
        try:
            message = client_sock.recv(4096)
            if not message:
                logging.info("Client disconnected")
                break

            if client_public_key is None:
                # The first message received should be an unencrypted hello message
                try:
                    decoded_message = message.decode()
                    print(f"Received message: {decoded_message}")
                    data = json.loads(decoded_message)
                    if data["data"]["type"] == "hello":
                        client_public_key = serialization.load_pem_public_key(data["data"]["public_key"].encode())
                        logging.info("Received client's public key from hello message")
                    else:
                        logging.warning(f"Expected hello message, but received {data['data']['type']}")
                except json.JSONDecodeError:
                    logging.error("Failed to decode JSON from the received message")
                except Exception as e:
                    logging.error(f"Error processing hello message: {str(e)}")
            else:
                # Make subsequent messages encrypted after receiving the "hello" message
                print(f"Received encrypted message: {message.hex()}")
                try:
                    decrypted_message = decrypt_message(message, private_key)
                    logging.info(f"Decrypted message: {decrypted_message}")

                    data, counter = parse_and_verify_message(decrypted_message, client_public_key)
                    
                    if data["type"] == "chat":
                        logging.info(f"Received chat message: {data['message']}")
                    else:
                        logging.warning(f"Received unknown message type: {data['type']}")
                except Exception as e:
                    logging.error(f"Error decrypting or parsing message: {str(e)}")

        except Exception as e:
            logging.error(f"Error processing message: {e}")
            logging.error(f"Error details: {str(e)}", exc_info=True)

    client_sock.close()
    logging.info("Closed client connection")

def start_server():
    logging.info("Starting server...")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("0.0.0.0", 8080))
    server_sock.listen(5)
    logging.info("Server started and listening on port 8080")

    while True:
        client_sock, addr = server_sock.accept()
        logging.info(f"Accepted connection from {addr}")
        handle_client(client_sock)

if __name__ == "__main__":
    start_server()
