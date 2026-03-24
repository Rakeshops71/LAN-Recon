import React from 'react';
import { Monitor, Smartphone, Globe, ShieldAlert, ShieldCheck, Activity } from 'lucide-react';

export default function DeviceCard({ device }) {
  // Threat score mapping (placeholder logic if not provided)
  const score = device.threatScore || 0;
  const isDanger = score > 60;
  const isWarning = score > 30;

  let borderColor = 'border-dark-600/50';
  let scoreColor = 'text-neon-green';
  
  if (isDanger) {
    borderColor = 'border-neon-red/50 shadow-[0_0_15px_rgba(239,68,68,0.2)]';
    scoreColor = 'text-neon-red glow-red';
  } else if (isWarning) {
    borderColor = 'border-neon-amber/50 shadow-[0_0_15px_rgba(245,158,11,0.2)]';
    scoreColor = 'text-neon-amber';
  }

  // Guess icon
  const osStr = (device.osGuess || '').toLowerCase();
  const isDesktop = osStr.includes('windows') || osStr.includes('mac') || osStr.includes('linux');

  return (
    <div className={`glass-panel rounded-xl p-5 flex flex-col gap-4 transition-all duration-300 hover:scale-[1.02] hover:-translate-y-1 cursor-pointer ${borderColor}`}>
      <div className="flex justify-between items-start">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-dark-700/80 rounded-lg">
            {isDesktop ? 
              <Monitor className="w-6 h-6 text-neon-cyan" /> :
              <Smartphone className="w-6 h-6 text-neon-purple" />
            }
          </div>
          <div>
            <h3 className="text-lg font-bold text-white tracking-wider font-mono">{device.ip}</h3>
            <p className="text-xs text-slate-400 font-mono">{device.mac}</p>
          </div>
        </div>
        <div className="flex flex-col items-end">
          <span className={`text-xl font-bold font-mono ${scoreColor}`}>{score}</span>
          <span className="text-[10px] uppercase tracking-widest text-slate-500">Threat</span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 mt-2">
        <div className="bg-dark-900/40 rounded p-2 flex flex-col border border-dark-600/30">
          <span className="text-[10px] uppercase text-slate-500 mb-0.5">Vendor</span>
          <span className="text-xs text-slate-300 truncate font-medium">{device.vendor || 'Unknown'}</span>
        </div>
        <div className="bg-dark-900/40 rounded p-2 flex flex-col border border-dark-600/30">
          <span className="text-[10px] uppercase text-slate-500 mb-0.5">OS Guess</span>
          <span className="text-xs text-slate-300 truncate font-medium">{device.osGuess || 'Unknown'}</span>
        </div>
      </div>

      <div className="flex items-center justify-between mt-1 pt-3 border-t border-dark-600/30">
        <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
          <Activity className="w-3.5 h-3.5 text-neon-cyan" />
          <span>{device.packets || 0} pkts</span>
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
          <Globe className="w-3.5 h-3.5 text-neon-purple" />
          <span>{device.dns?.length || 0} domains</span>
        </div>
      </div>
    </div>
  );
}
