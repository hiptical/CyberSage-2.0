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
  const [backendUrl, setBackendUrl] = useState(null);

  useEffect(() => {
    // Dynamic backend URL detection with auto-discovery
    const detectBackendUrl = async () => {
      const possibleUrls = [];

      // Priority 1: Environment variable
      if (process.env.REACT_APP_BACKEND_URL) {
        possibleUrls.push(process.env.REACT_APP_BACKEND_URL);
      }

      // Priority 2: Same host (production deployment)
      const currentHost = window.location.hostname;
      const currentProtocol = window.location.protocol;
      possibleUrls.push(`${currentProtocol}//${currentHost}:5000`);

      // Priority 3: Localhost variations (development)
      if (currentHost === 'localhost' || currentHost === '127.0.0.1') {
        possibleUrls.push('http://localhost:5000');
        possibleUrls.push('http://127.0.0.1:5000');
      }

      // Priority 4: Local network discovery (if frontend is on different machine)
      const ipMatch = currentHost.match(/^(\d+\.\d+\.\d+)\.\d+$/);
      if (ipMatch) {
        const networkPrefix = ipMatch[1];
        // Try common gateway IPs in the same subnet
        for (let i = 1; i <= 254; i++) {
          if (i !== parseInt(currentHost.split('.')[3])) {
            possibleUrls.push(`http://${networkPrefix}.${i}:5000`);
          }
        }
      }

      // Test each URL to find working backend
      for (const url of possibleUrls) {
        try {
          console.log(`[WebSocket] Testing backend at: ${url}`);
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 2000);

          const response = await fetch(`${url}/api/health`, {
            signal: controller.signal,
            mode: 'cors'
          });

          clearTimeout(timeoutId);

          if (response.ok) {
            const data = await response.json();
            if (data.status === 'healthy') {
              console.log(`✅ [WebSocket] Found backend at: ${url}`);
              return url;
            }
          }
        } catch (error) {
          // Silently continue to next URL
        }
      }

      // Fallback to localhost
      console.warn('[WebSocket] No backend found, using localhost fallback');
      return 'http://localhost:5000';
    };

    // Initialize connection
    const initializeSocket = async () => {
      const discoveredUrl = await detectBackendUrl();
      setBackendUrl(discoveredUrl);
      console.log('[WebSocket] Connecting to:', discoveredUrl);

      // Create socket connection with proper configuration
      // Using Socket.IO v4 protocol (EIO=4)
      const newSocket = io(`${discoveredUrl}/scan`, {
        transports: ['polling', 'websocket'],
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000,
        reconnectionAttempts: 10,
        timeout: 20000,
        upgrade: true,
        forceNew: true,
        autoConnect: true,
        withCredentials: false,
        path: '/socket.io',
        // Force Socket.IO v4 protocol
        extraHeaders: {
          'Accept': 'application/json'
        }
      });

      // Connection event handlers
      newSocket.on('connect', () => {
        console.log('✅ [WebSocket] Connected - Socket ID:', newSocket.id);
        console.log('✅ [WebSocket] Backend URL:', discoveredUrl);
        console.log('✅ [WebSocket] Transport:', newSocket.io.engine.transport.name);
        setConnected(true);
        setReconnecting(false);
      });

      newSocket.on('disconnect', (reason) => {
        console.log('❌ [WebSocket] Disconnected. Reason:', reason);
        setConnected(false);
        if (reason === 'io server disconnect') {
          // Server disconnected, need to manually reconnect
          setTimeout(() => newSocket.connect(), 1000);
        }
      });

      newSocket.on('connect_error', (error) => {
        console.error('❌ [WebSocket] Connection error:', error.message);
        console.error('   Attempted URL:', discoveredUrl);
        console.error('   Error type:', error.type);
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
        console.log('🏓 [WebSocket] Pong received - Connection healthy');
      });

      // Backend-specific events
      newSocket.on('connected', (data) => {
        console.log('🎉 [Backend] Connected event received:', data);
      });

      setSocket(newSocket);

      // Cleanup on unmount
      return () => {
        console.log('[WebSocket] Cleaning up connection');
        newSocket.close();
      };
    };

    initializeSocket();
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

  // Helper function to get current backend URL
  const getBackendUrl = () => {
    return backendUrl;
  };

  return { 
    socket, 
    connected, 
    reconnecting,
    checkConnection,
    reconnect,
    backendUrl: getBackendUrl()
  };
};