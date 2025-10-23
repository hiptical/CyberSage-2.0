import { useState, useEffect } from 'react';
import { io } from 'socket.io-client';

/**
 * Custom WebSocket Hook for CyberSage v2.0
 * Automatically detects backend URL and handles reconnection
 */
export const useWebSocket = () => {
  const [socket, setSocket] = useState(null);
  const [connected, setConnected] = useState(false);
  const [reconnecting, setReconnecting] = useState(false);

  useEffect(() => {
    // Dynamic backend URL detection
    const getBackendUrl = () => {
      // Priority 1: Environment variable
      if (process.env.REACT_APP_BACKEND_URL) {
        return process.env.REACT_APP_BACKEND_URL;
      }

      // Priority 2: Current host (for production/same-server deployment)
      const currentHost = window.location.hostname;
      const currentProtocol = window.location.protocol;
      
      // If running on non-localhost, use current host with port 5000
      if (currentHost !== 'localhost' && currentHost !== '127.0.0.1') {
        return `${currentProtocol}//${currentHost}:5000`;
      }

      // Priority 3: Default to localhost (development)
      return 'http://localhost:5000';
    };

    const backendUrl = getBackendUrl();
    console.log('[WebSocket] Connecting to:', backendUrl);

    // Create socket connection
    const newSocket = io(`${backendUrl}/scan`, {
      transports: ['polling', 'websocket'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      reconnectionAttempts: 10,
      timeout: 20000,
      upgrade: true,
      forceNew: true,
      autoConnect: true,
      withCredentials: false
    });

    // Connection event handlers
    newSocket.on('connect', () => {
      console.log('✅ [WebSocket] Connected - Socket ID:', newSocket.id);
      setConnected(true);
      setReconnecting(false);
    });

    newSocket.on('disconnect', (reason) => {
      console.log('❌ [WebSocket] Disconnected. Reason:', reason);
      setConnected(false);
      if (reason === 'io server disconnect') {
        // Server disconnected, need to manually reconnect
        newSocket.connect();
      }
    });

    newSocket.on('connect_error', (error) => {
      console.error('❌ [WebSocket] Connection error:', error.message);
      setConnected(false);
      setReconnecting(true);
    });

    newSocket.on('reconnect_attempt', (attemptNumber) => {
      console.log(`🔄 [WebSocket] Reconnection attempt ${attemptNumber}...`);
      setReconnecting(true);
    });

    newSocket.on('reconnect', (attemptNumber) => {
      console.log(`✅ [WebSocket] Reconnected after ${attemptNumber} attempts`);
      setConnected(true);
      setReconnecting(false);
    });

    newSocket.on('reconnect_failed', () => {
      console.error('❌ [WebSocket] Reconnection failed after all attempts');
      setConnected(false);
      setReconnecting(false);
    });

    newSocket.on('error', (error) => {
      console.error('❌ [WebSocket] Socket error:', error);
    });

    // Handle ping/pong for connection health
    newSocket.on('pong', () => {
      console.log('🏓 [WebSocket] Pong received');
    });

    setSocket(newSocket);

    // Cleanup on unmount
    return () => {
      console.log('[WebSocket] Cleaning up connection');
      newSocket.close();
    };
  }, []);

  // Helper function to check connection health
  const checkConnection = () => {
    if (socket && socket.connected) {
      socket.emit('ping');
      return true;
    }
    return false;
  };

  // Helper function to manually reconnect
  const reconnect = () => {
    if (socket) {
      console.log('[WebSocket] Manual reconnection triggered');
      socket.connect();
    }
  };

  return { 
    socket, 
    connected, 
    reconnecting,
    checkConnection,
    reconnect
  };
};