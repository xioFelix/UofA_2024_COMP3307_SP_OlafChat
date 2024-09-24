
# OLAF Chat System

## Overview

The OLAF Chat System is a secure, distributed chat application that facilitates encrypted communication between users. It employs AES encryption, RSA key exchange, and digital signatures to ensure confidentiality, integrity, and authentication of messages. This project is part of an Advanced Secure Programming assignment, focusing on secure communication protocols and ethical vulnerabilities.

## Features

- **Secure Client-Server Communication**: Encrypted messaging between clients and servers using a distributed architecture.
- **AES Encryption**: Messages are encrypted using AES in CFB mode, ensuring confidentiality during transmission.
- **RSA Key Exchange**: Clients and servers use RSA for secure exchange of AES session keys.
- **Authentication**: Servers authenticate clients upon connection using RSA-signed messages.
- **Replay Attack Prevention**: Messages are protected against replay attacks using a counter mechanism.
- **Digital Signatures**: Ensures message integrity and authenticity by signing messages with RSA.
- **Private Messaging**: Users can send encrypted private messages to specific users.
- **Broadcast Messaging**: Send messages to all online users.
- **File Transfer**: Upload and download files securely, with options for public or private sharing.
- **Notifications**: Users receive notifications when new public files are uploaded or when they receive private files.
- **Downloadable File List**: Users can request a list of files available for them to download.

## Getting Started

### Prerequisites
- Python 3.x installed on your system.
- Install the required dependencies listed in `requirements.txt`.

### Installation

#### Clone the Repository:
```bash
git clone https://github.com/<YourUserName>/UofA_2024_SP_OlafChat.git
cd UofA_2024_SP_OlafChat
```

#### Install Dependencies:
```bash
pip install -r requirements.txt
```

### Running the Server

#### Start the Server:
```bash
python server/server.py
```
The server is responsible for accepting client connections, handling authentication, relaying encrypted messages, and managing file transfers.

### Server Output
The server will display output indicating:
- Client connections and disconnections.
- RSA public key exchanges.
- Encrypted and decrypted messages.
- File uploads and downloads.
- Notifications sent to users.

### Running the Client

#### Start the Client:
```bash
python client/client.py
```
The client connects to the server, exchanges public keys, and allows the user to send encrypted messages and files.

### Client Commands
Once connected, the client supports the following commands:

- **List Online Users**:
```plaintext
/list
```

- **Send a Broadcast Message**:
```plaintext
/all <message>
```

- **Send a Private Message**:
```plaintext
/msg <username> <message>
```

- **Upload a File**:

  - **Public Upload**:
  ```plaintext
  /upload <filename>
  ```

  - **Private Upload**:
  ```plaintext
  /upload <filename> <username>
  ```

- **Download a File**:
```plaintext
/download <filename>
```

- **List Downloadable Files**:
```plaintext
/files
```

- **Show Help**:
```plaintext
/help
```

- **Exit the Chat**:
```plaintext
quit
```

### Sending Messages

- **Broadcast Message**: Use `/all` followed by your message to send a message to all online users.
- **Private Message**: Use `/msg` followed by the username and your message to send a private message.

### File Transfer

#### Uploading Files:
- **Public File**: Upload a file that all users can download:
```plaintext
/upload example.txt
```

- **Private File**: Upload a file for a specific user:
```plaintext
/upload example.txt recipient_username
```

#### Downloading Files:
- **Request a list of available files**:
```plaintext
/files
```

- **Download a file from the list**:
```plaintext
/download example.txt
```

- **File Storage**:
Downloaded files are saved in a directory named after your username, e.g., `username_files/`.

### Receiving Notifications

#### File Upload Notifications:
- When a user uploads a public file, all users receive a notification:
```plaintext
[Notification]: username has uploaded a new public file 'example.txt'.
```

- When a private file is uploaded for you, you receive a notification:
```plaintext
[Notification]: username has uploaded a file 'example.txt' for you.
```

### Exit the Client
To exit the client, type:
```plaintext
quit
```

## Encryption and Security

- **AES Encryption**: Uses AES in CFB mode for message encryption, ensuring confidentiality.
- **RSA Key Exchange**: RSA is used for exchanging AES session keys securely between clients and servers.
- **Digital Signatures**: Messages are signed using RSA to ensure integrity and authenticity.
- **Replay Attack Prevention**: A counter mechanism is used to prevent replay attacks.
- **Shared Keys for Private Messaging**: Clients establish shared AES keys for encrypted private messaging.

## Example Workflow

- **Start the Server**:
```bash
python server/server.py
```

- **Start the Client**:
```bash
python client/client.py
```

- **Register or Login**:
  - Enter your username.
  - Choose to register or login.

- **List Online Users**:
```plaintext
/list
```

- **Send a Broadcast Message**:
```plaintext
/all Hello everyone!
```

- **Send a Private Message**:
```plaintext
/msg alice Hi Alice!
```

- **Upload a Public File**:
```plaintext
/upload document.pdf
```

- **Upload a Private File**:
```plaintext
/upload secrets.txt bob
```

- **Download a File**:
  - **List available files**:
  ```plaintext
  /files
  ```

  - **Download a file**:
  ```plaintext
  /download document.pdf
  ```

## Project Structure

```plaintext
├── client/
│   ├── client.py          # Client-side implementation
│   ├── shared/
│       ├── encryption.py  # Encryption functions shared by client and server
├── server/
│   ├── server.py          # Server-side implementation
│   ├── auth.py            # User authentication management
│   ├── shared/
│       ├── encryption.py  # Encryption functions shared by client and server
├── server_files/          # Directory where server stores uploaded files
├── username_files/        # Directories where clients store downloaded files (one per user)
├── requirements.txt       # List of Python dependencies
```

## Troubleshooting

- **Connection Refused**:
  - Ensure that the server is running.
  - Verify the IP address and port number in `client.py`.

- **Signature Verification Failed**:
  - Ensure that the message has not been tampered with.
  - Verify that the correct public keys are being used.

- **File Not Found**:
  - Check if the file exists in the specified directory.
  - Ensure you have permission to access the file.

- **Permission Denied for File Download**:
  - You may not have permission to download the requested file.
  - Use `/files` to see the list of files you can download.

## Security Considerations

- **Key Management**: Each user has a unique RSA key pair for authentication and encryption.
- **Secure Communication**: All messages and file transfers are encrypted to prevent eavesdropping.
- **Access Control**: File permissions are enforced to prevent unauthorized access.
- **Integrity Checks**: Digital signatures are used to verify the integrity of messages.

## Contribution

If you would like to contribute to this project, feel free to fork the repository and submit a pull request. Contributions for adding new features, improving security, or fixing bugs are welcome.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.

## Future Enhancements

- **Shared Key Confirmation**: Implement confirmation for shared keys to improve reliability.
- **Message History**: Store and retrieve chat history.
- **User Presence Notifications**: Notify users when others log in or out.
- **Graphical User Interface**: Develop a GUI for improved user experience.
- **Enhanced Error Handling**: Improve feedback for various error scenarios.
- **Group Chat Support**: Enable users to create and join group chats.
- **File Transfer Progress**: Show progress indicators during file uploads/downloads.

*Note: Replace `<YourUserName>` in the repository URL with your actual GitHub username.*
