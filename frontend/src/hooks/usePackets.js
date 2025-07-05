import { useEffect, useRef, useState, useCallback } from 'react';
import { io } from 'socket.io-client';

export default function usePackets() {
  const [packets, setPackets] = useState([]);
  const [isPaused, setIsPaused] = useState(false);
  const socketRef = useRef(null);

  const handlePacket = useCallback((data) => {
    if (!isPaused) {
      setPackets(prev => [data, ...prev.slice(0, 49)]);
    }
  }, [isPaused]);

  useEffect(() => {
    const socketUrl = process.env.REACT_APP_SOCKET_URL || 'http://localhost:5000';
    socketRef.current = io(socketUrl);

    socketRef.current.on('packet', handlePacket);

    return () => {
      socketRef.current?.off('packet', handlePacket);
      socketRef.current?.disconnect();
    };
  }, [handlePacket]);

  const togglePause = () => setIsPaused(prev => !prev);

  return { packets, isPaused, togglePause };
}
