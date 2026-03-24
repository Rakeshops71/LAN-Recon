import React, { useState, useEffect, useRef } from 'react';
import DeviceCard from './components/DeviceCard';
import EventFeed from './components/EventFeed';
import MitmPanel from './components/MitmPanel';
import { Shield, Radio, Activity, Radar, Lock, Skull } from 'lucide-react';

function App() {
  const [devices, setDevices] = useState([]);
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);
  const [mitmStatus, setMitmStatus] = useState({ active: false, target: null });
  const wsRef = useRef(null);

  useEffect(() => {
    let ws;
    let reconnectTimer;

    const connect = () => {
      ws = new WebSocket('ws://localhost:8080');
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
      };

      ws.onmessage = (msg) => {
        try {
          const data = JSON.parse(msg.data);
          if (data.type === 'init' || data.type === 'snapshot') {
            if (data.devices) setDevices(data.devices);
            if (data.events) setEvents(data.events);
          } else if (data.type === 'event') {
            if (data.event) {
              setEvents(prev => [...prev.slice(-199), data.event]);
            }
            if (data.devices) setDevices(data.devices);
          } else if (data.type === 'mitm_status') {
            setMitmStatus({ active: data.active, target: data.target });
          }
        } catch (e) {
          console.error("Failed to parse websocket message", e);
        }
      };

      ws.onclose = () => {
        setConnected(false);
        reconnectTimer = setTimeout(connect, 3000);
      };
      
      ws.onerror = () => {
        ws.close();
      };
    };

    connect();

    return () => {
      if (ws) ws.close();
      clearTimeout(reconnectTimer);
    };
  }, []);

  const handleStartMitm = (targetIp, gatewayIp) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: 'mitm_cmd', action: 'start', targetIp, gatewayIp }));
    }
  };

  const handleStopMitm = () => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: 'mitm_cmd', action: 'stop' }));
    }
  };

  return (
    <div className="bg-dark-900 text-slate-300 font-sans p-6 flex flex-col h-screen overflow-hidden antialiased">
      {/* Header */}
      <header className="flex items-center justify-between mb-6 pb-5 border-b border-dark-600/50">
        <div className="flex items-center gap-5">
          <div className="relative">
            <Radar className={`w-10 h-10 ${connected ? 'text-neon-cyan animate-[spin_4s_linear_infinite]' : 'text-slate-600'}`} />
            {connected && <div className="absolute inset-0 bg-neon-cyan/20 blur-xl rounded-full"></div>}
          </div>
          <div className="flex flex-col">
            <h1 className="text-3xl font-extrabold text-white tracking-[0.2em] uppercase flex items-center gap-3">
              LAN Recon
              {mitmStatus.active && <span className="bg-neon-red text-white text-[10px] px-2 py-0.5 rounded-full animate-pulse ml-2">ATTACK ACTIVE</span>}
            </h1>
            <p className="text-xs text-neon-cyan tracking-[0.3em] font-mono mt-0.5 opacity-80">Network Surveillance & Attack Simulation</p>
          </div>
        </div>
        
        <div className="flex items-center gap-8">
          <div className="flex flex-col items-end">
            <span className="text-[10px] uppercase text-slate-500 tracking-[0.2em] mb-1">Datalink Status</span>
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${connected ? 'bg-neon-green glow-green animate-pulse' : 'bg-neon-red glow-red'}`}></div>
              <span className={`text-sm font-bold font-mono tracking-widest ${connected ? 'text-neon-green' : 'text-neon-red'}`}>
                {connected ? 'ACQUIRED' : 'DISCONNECTED'}
              </span>
            </div>
          </div>
          <div className="flex flex-col items-end pl-8 border-l border-dark-600/50">
            <span className="text-[10px] uppercase text-slate-500 tracking-[0.2em] mb-1">Active Targets</span>
            <span className="text-3xl font-bold text-white font-mono leading-none">{devices.length}</span>
          </div>
          <div className="flex flex-col items-end pl-8 border-l border-dark-600/50">
            <span className="text-[10px] uppercase text-slate-500 tracking-[0.2em] mb-1">Mode</span>
            <div className={`flex items-center gap-1.5 ${mitmStatus.active ? 'text-neon-red' : 'text-neon-amber'}`}>
               {mitmStatus.active ? <Skull className="w-4 h-4" /> : <Lock className="w-4 h-4" />}
               <span className="text-sm font-bold font-mono tracking-widest uppercase">
                 {mitmStatus.active ? 'MITM Attack' : 'Passive Spy'}
               </span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Layout Grid */}
      <main className="flex-1 grid grid-cols-12 gap-6 min-h-0">
        
        {/* Device Grid */}
        <div className="col-span-8 lg:col-span-9 overflow-y-auto pr-2 pb-4 scroll-smooth">
          {devices.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-slate-500 gap-5 opacity-40">
               <Shield className="w-20 h-20 mb-2" />
               <p className="text-xl uppercase tracking-[0.3em] font-mono">No devices detected</p>
               <p className="text-sm font-mono tracking-widest">Awaiting ARP or DNS packets on network interface...</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
              {devices.map(dev => (
                <DeviceCard key={dev.ip} device={dev} />
              ))}
            </div>
          )}
        </div>

        {/* Live Event Stream & Controls */}
        <div className="col-span-4 lg:col-span-3 min-h-0 pb-4 h-full flex flex-col gap-6">
          <MitmPanel 
             devices={devices} 
             mitmStatus={mitmStatus} 
             onStartMitm={handleStartMitm} 
             onStopMitm={handleStopMitm} 
          />
          <div className="flex-1 min-h-0">
            <EventFeed events={events} />
          </div>
        </div>
        
      </main>
    </div>
  );
}

export default App;