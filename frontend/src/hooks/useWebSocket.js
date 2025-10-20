import { useEffect, useState } from 'react';
import { io } from 'socket.io-client';

export const useWebSocket = () => {
  const [socket, setSocket] = useState(null);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    // Determine backend URL
    const backendUrl = process.env.REACT_APP_BACKEND_URL || 
                       `${window.location.protocol}//${window.location.hostname}:5000`;
    
    console.log('Connecting to WebSocket:', backendUrl);

    const newSocket = io(`${backendUrl}/scan`, {
      transports: ['websocket', 'polling'], // Try websocket first, fallback to polling
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