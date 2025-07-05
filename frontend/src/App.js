import { useState, useMemo } from 'react';
import Header      from './components/Header';       
import FilterBar   from './components/FilterBar';    
import PacketTable from './components/PacketTable';  
import usePackets  from './hooks/usePackets';        
import './App.css';                                  

export default function App() {
  const { packets, isPaused, togglePause } = usePackets(); 
  const [selectedPort, setSelectedPort] = useState('all'); 

  
  const visiblePackets = useMemo(() => {
    if (selectedPort === 'all') return packets; 
    const port = Number(selectedPort);          
    return packets.filter(p => p.src_port === port || p.dest_port === port); 
  }, [packets, selectedPort]);

  return (
    <div className="App">
      <Header paused={isPaused} onToggle={togglePause} /> {}

      <FilterBar
        value={selectedPort}             // Current selected port
        onChange={setSelectedPort}       // Update selected port
        options={[                       // Dropdown options
          { value: 'all', label: 'Show all' },
          { value: 80,   label: '80 (HTTP)' },
          { value: 443,  label: '443 (HTTPS)' },
          { value: 53,   label: '53 (DNS)' },
          { value: 22,   label: '22 (SSH)' },
          { value: 8009, label: '8009 (Chromecast)' },
        ]}
      />

      <PacketTable packets={visiblePackets} /> {}
    </div>
  );
}
