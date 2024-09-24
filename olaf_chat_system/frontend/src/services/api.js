let socket;

export const connectToServer = (clientId) => {
    socket = new WebSocket(`ws://localhost:8000/ws/${clientId}`);

    socket.onmessage = (event) => {
        console.log('Message from server ', event.data);
    };

    socket.onclose = () => {
        console.log('Connection closed');
    };
};

export const sendMessage = (message) => {
    if (socket) {
        socket.send(message);
    }
};
