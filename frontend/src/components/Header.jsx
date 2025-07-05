import { FaPause, FaPlay } from 'react-icons/fa';

export default function Header({ paused, onToggle }) {
  return (
    <header className="header">
      <h1>Packet Sniffer Dashboard</h1>
      <button className="pause-button" onClick={onToggle}>
        {paused ? <><FaPlay /> Resume</> : <><FaPause /> Pause</>}
      </button>
    </header>
  );
}
