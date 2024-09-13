
# OLAF Chat System

## Overview
The OLAF Chat System is a secure, distributed chat application that uses **AES encryption** and **RSA key exchange** to ensure the confidentiality and integrity of messages exchanged between clients and servers. This project is part of an Advanced Secure Programming assignment, focusing on secure communication protocols, including encryption, message integrity, and ethical vulnerabilities.

## Features
- **Client-Server Communication**: Secure messaging between clients and servers using a distributed client-server architecture.
- **AES Encryption**: Messages are encrypted using **AES in CFB mode**, ensuring confidentiality during transmission.
- **RSA Key Exchange**: Clients and servers use RSA for secure key exchange of the AES session key.
- **Authentication**: Servers authenticate clients upon connection using RSA-signed messages.
- **Replay Attack Prevention**: Messages are protected against replay attacks using a counter mechanism.
- **Decryption**: Clients can decrypt received messages for secure communication.
- **Message Signing**: Ensures message integrity by using digital signatures.

## Getting Started

### Prerequisites
- Python 3.x installed on your system.
- Install the required dependencies listed in `requirements.txt`.

### Installation

1. Clone the Repository:
   ```bash
   git clone https://github.com/<Your User Name>/UofA_2024_SP_OlafChat.git
   cd UofA_2024_SP_OlafChat
   ```

2. Install Dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running the Server

Start the Server:
```bash
./scripts/run_server.sh
```
The server is responsible for accepting client connections, exchanging RSA public keys, and relaying encrypted messages. The server logs encryption, decryption, and received messages.

### Server Output:
The server will display output indicating:
- When a client connects.
- The RSA public key exchange.
- Encrypted and decrypted messages.

### Running the Client

Start the Client:
```bash
./scripts/run_client.sh
```
The client connects to the server, exchanges public keys, and allows the user to send encrypted messages.

### Sending Messages:
Once the client is connected, you can type messages into the console. These messages will be signed, encrypted using AES, and sent to the server.

### Receiving Messages:
The client will display decrypted messages received from the server.

### Exit the Client:
To exit the client, type `quit`.

## Encryption and Decryption

- **Encryption**: Messages are encrypted using AES in CFB mode. RSA is used for the initial key exchange.
- **Decryption**: Received messages are decrypted using the AES key shared during the RSA key exchange.
- **Message Signing**: Each message is signed using RSA to ensure message integrity and authenticity.
- **Replay Attack Prevention**: A counter is used to prevent replay attacks.

## Example Workflow

1. **Start the Server**:
   ```bash
   ./scripts/run_server.sh
   ```

2. **Start the Client**:
   ```bash
   ./scripts/run_client.sh
   ```

3. **Send and Receive Messages**:
   - The client sends an encrypted and signed message.
   - The server receives, decrypts, verifies the signature, and displays the message.

## Project Structure

```plaintext
├── client/
│   ├── client.py          # Client-side implementation
├── server/
│   ├── server.py          # Server-side implementation
├── shared/
│   ├── encryption.py      # Encryption and decryption functions (shared by client and server)
├── protocol/              # Protocol implementation (if applicable)
├── tests/                 # Unit and integration tests
├── docs/                  # Documentation files for the project
├── scripts/               # Shell scripts to run the client and server
├── requirements.txt       # List of Python dependencies
```

### Troubleshooting

1. **Connection Refused**: Ensure that the server is running and the IP address and port are correct.
2. **Signature Verification Failed**: Ensure that the message has not been tampered with, and the keys match.
3. **Invalid Padding/IV Size**: Ensure that the AES IV and padding are correctly implemented.

### Contribution
If you would like to contribute to this project, feel free to fork the repository and submit a pull request. Contributions for adding new features, improving security, or fixing bugs are welcome.

### License
This project is licensed under the MIT License. See the LICENSE file for more details.
