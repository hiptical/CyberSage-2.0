// frontend/src/hooks/useWebSocket.js
import { useState, useEffect } from 'react';
import { io } from 'socket.io-client';

export const useWebSocket = () => {
  const [socket, setSocket] = useState(null);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:5000';
    
    console.log('🔌 Connecting to WebSocket:', `${backendUrl}/scan`);

    const newSocket = io(`${backendUrl}/scan`, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: 10,
      timeout: 20000,
      autoConnect: true
    });

    newSocket.on('connect', () => {
      console.log('✅ WebSocket Connected!');
      setConnected(true);
    });

    newSocket.on('disconnect', (reason) => {
      console.log('❌ WebSocket Disconnected:', reason);
      setConnected(false);
    });

    newSocket.on('connect_error', (error) => {
      console.error('🔴 WebSocket Connection Error:', error.message);
      setConnected(false);
    });

    newSocket.on('error', (error) => {
      console.error('🔴 WebSocket Error:', error);
    });

    setSocket(newSocket);

    return () => {
      console.log('Cleaning up WebSocket connection');
      newSocket.close();
    };
  }, []);

  return { socket, connected };
};

export default useWebSocket;