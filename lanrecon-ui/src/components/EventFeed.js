import React, { useEffect, useRef } from 'react';
import { Terminal, Activity, Globe, ShieldAlert, Network, Wifi } from 'lucide-react';

export default function EventFeed({ events }) {
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [events]);

  return (
    <div className="glass-panel flex flex-col h-full rounded-xl overflow-hidden border-dark-600/50">
      <div className="bg-dark-800/80 p-3 border-b border-dark-600/50 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-neon-cyan" />
          <h2 className="text-xs font-bold text-slate-200 tracking-[0.2em] uppercase">Live Activity Stream</h2>
        </div>
        <div className="flex items-center gap-2">
           <span className="relative flex h-2 w-2">
             <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-neon-green opacity-75"></span>
             <span className="relative inline-flex rounded-full h-2 w-2 bg-neon-green"></span>
           </span>
           <span className="text-[10px] uppercase tracking-widest text-slate-400">Capturing</span>
        </div>
      </div>
      
      <div className="flex-1 overflow-y-auto p-4 space-y-2.5 font-mono text-xs bg-dark-900/20">
        {events.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full text-slate-500 gap-3 opacity-50">
            <Wifi className="w-8 h-8 animate-pulse" />
            <span className="uppercase tracking-widest text-[10px]">Listening on Interface</span>
          </div>
        )}
        
        {events.map((ev, i) => {
          let Icon = Activity;
          let textColor = 'text-slate-400';
          let iconColor = 'text-slate-500';
          let bg = 'bg-dark-800/40';

          if (ev.type === 'dns') {
            Icon = Globe;
            iconColor = 'text-neon-cyan glow-cyan';
            textColor = 'text-cyan-100';
            bg = 'bg-cyan-950/20 border-l border-cyan-800/30';
          } else if (ev.type === 'osfp' || ev.type === 'tcp') {
            Icon = Network;
            iconColor = 'text-neon-purple';
            textColor = 'text-purple-100';
            bg = 'bg-purple-950/20 border-l border-purple-800/30';
          } else if (ev.type === 'arp' || ev.type === 'dhcp') {
            Icon = Activity;
            iconColor = 'text-neon-green';
            textColor = 'text-green-100';
            bg = 'bg-green-950/20 border-l border-green-800/30';
          }

          return (
            <div key={i} className={`flex items-start gap-3 p-2.5 rounded transition-colors ${bg}`}>
              <Icon className={`w-4 h-4 mt-0.5 ${iconColor}`} />
              <div className="flex-1 min-w-0">
                <div className="flex justify-between items-center mb-1">
                  <span className="font-bold text-white">{ev.ip || 'Unknown'}</span>
                  <span className="text-slate-500 text-[10px]">
                    {new Date(ev.ts || Date.now()).toLocaleTimeString()}
                  </span>
                </div>
                <div className={`truncate break-words whitespace-normal ${textColor} leading-relaxed`}>
                  <span className="uppercase text-[9px] bg-dark-900 border border-dark-600/50 px-1.5 py-0.5 rounded mr-2 tracking-wider text-slate-400">
                    {ev.type}
                  </span>
                  {ev.detail || 'Packet received'}
                </div>
              </div>
            </div>
          );
        })}
        <div ref={bottomRef} className="h-1" />
      </div>
    </div>
  );
}
