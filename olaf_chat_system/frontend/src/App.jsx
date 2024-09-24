import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import { generateKeyPair, signMessage, importPrivateKey } from './crypto';

const ChatApp = () => {
  const [input, setInput] = useState('');
  const [messages, setMessages] = useState([]);
  const [socket, setSocket] = useState(null);
  const [username, setUsername] = useState('');
  const [recipient, setRecipient] = useState('');
  const [privateKey, setPrivateKey] = useState(null);
  const [publicKey, setPublicKey] = useState(null);

  const handleRegister = async () => {
    const { publicKey, privateKey } = await generateKeyPair();
    setPrivateKey(privateKey);

    const publicKeyPem = btoa(String.fromCharCode(...new Uint8Array(publicKey)));

    const result = await axios.post('http://localhost:8000/register', {
      username,
      publicKey: publicKeyPem
    });

    console.log('Registered:', result.data);
  };

  const handleLogin = async () => {
    const result = await axios.post('http://localhost:8000/login', { username });

    const importedPrivateKey = await importPrivateKey(result.data.private_key);
    setPrivateKey(importedPrivateKey);

    console.log('Logged in and set private key');
  };

  useEffect(() => {
    if (privateKey) {
      const ws = new WebSocket(`ws://localhost:8000/ws/${uuidv4()}`);

      ws.onopen = () => {
        console.log(`WebSocket connection opened`);
      };

      ws.onmessage = (event) => {
        const decryptedMessage = event.data;
        console.log('Message received:', decryptedMessage);
        setMessages((prevMessages) => [...prevMessages, decryptedMessage]);
      };

      ws.onclose = () => {
        console.log(`WebSocket connection closed`);
      };

      setSocket(ws);

      return () => {
        ws.close();
      };
    }
  }, [privateKey]);

  const sendMessage = async (event) => {
    event.preventDefault();
    if (input.trim() && socket && privateKey) {
      const signature = await signMessage(privateKey, input);
      const message = {
        type: recipient ? 'private' : 'broadcast',
        message: input,
        sender: username,
        recipient,
        signature: btoa(String.fromCharCode(...new Uint8Array(signature)))  // Convert ArrayBuffer to Base64
      };
      socket.send(JSON.stringify(message));
      setInput('');
    }
  };

  return (
    <div>
      <h1>Chat App</h1>
      <input
        type="text"
        placeholder="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
      />
      <button onClick={handleRegister}>Register</button>
      <button onClick={handleLogin}>Login</button>

      <div>
        {messages.map((msg, index) => (
          <p key={index}>{msg}</p>
        ))}
      </div>
      <input
        type="text"
        placeholder="Recipient ID (optional for private message)"
        value={recipient}
        onChange={(e) => setRecipient(e.target.value)}
      />
      <input
        type="text"
        value={input}
        onChange={(e) => setInput(e.target.value)}
      />
      <button onClick={sendMessage}>Send</button>
    </div>
  );
};

export default ChatApp;
