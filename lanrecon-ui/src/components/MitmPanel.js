import React, { useState } from 'react';
import { Skull, Shield, Server, Crosshair } from 'lucide-react';

export default function MitmPanel({ devices, mitmStatus, onStartMitm, onStopMitm }) {
  const [selectedIp, setSelectedIp] = useState('');
  const [gatewayIp, setGatewayIp] = useState('192.168.1.1');

  const handleStart = () => {
    if (selectedIp && gatewayIp) {
      onStartMitm(selectedIp, gatewayIp);
    }
  };

  return (
    <div className={`glass-panel p-5 rounded-xl border-l-4 transition-all duration-300 ${mitmStatus?.active ? 'border-neon-red shadow-[0_0_20px_rgba(239,68,68,0.3)] bg-red-950/20' : 'border-dark-600/50'}`}>
      <div className="flex items-center gap-3 mb-5">
        {mitmStatus?.active ? <Skull className="w-5 h-5 text-neon-red animate-pulse" /> : <Shield className="w-5 h-5 text-slate-400" />}
        <h2 className={`font-mono text-sm font-bold tracking-widest uppercase ${mitmStatus?.active ? 'text-neon-red glow-red' : 'text-slate-300'}`}>
          MITM Engine Control
        </h2>
      </div>

      <div className="flex flex-col gap-4">
        <div className="flex flex-col gap-1.5">
          <label className="text-[10px] uppercase text-slate-500 tracking-[0.2em] font-bold">Target Target</label>
          <select 
            className="bg-dark-900 border border-dark-600 rounded p-2 text-sm text-slate-200 outline-none focus:border-neon-red transition-colors font-mono"
            value={selectedIp}
            onChange={e => setSelectedIp(e.target.value)}
            disabled={mitmStatus?.active}
          >
            <option value="">Select Target IP...</option>
            {devices.map(d => (
              <option key={d.ip} value={d.ip}>{d.ip} {d.vendor ? `(${d.vendor.split(' ')[0]})` : ''}</option>
            ))}
          </select>
        </div>

        <div className="flex flex-col gap-1.5">
          <label className="text-[10px] uppercase text-slate-500 tracking-[0.2em] font-bold">Gateway / Router IP</label>
          <div className="relative">
            <Server className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
            <input 
              type="text" 
              className="w-full bg-dark-900 border border-dark-600 rounded p-2 pl-9 text-sm text-slate-200 outline-none focus:border-neon-red transition-colors font-mono"
              placeholder="e.g. 192.168.1.1"
              value={gatewayIp}
              onChange={e => setGatewayIp(e.target.value)}
              disabled={mitmStatus?.active}
            />
          </div>
        </div>

        <div className="pt-3">
          {mitmStatus?.active ? (
            <button 
              onClick={onStopMitm}
              className="w-full bg-dark-800 border-2 border-neon-red text-neon-red font-bold uppercase tracking-[0.3em] py-3 text-xs rounded-lg flex justify-center items-center gap-2 hover:bg-neon-red hover:text-white transition-all glow-red"
            >
              <Skull className="w-4 h-4" /> Disarm Attack
            </button>
          ) : (
            <button 
              onClick={handleStart}
              disabled={!selectedIp || !gatewayIp}
              className={`w-full border-2 font-bold uppercase tracking-[0.3em] py-3 text-xs rounded-lg flex justify-center items-center gap-2 transition-all duration-300 ${
                selectedIp && gatewayIp 
                ? 'border-neon-red text-neon-red hover:bg-neon-red/10 cursor-pointer shadow-[0_0_10px_rgba(239,68,68,0.1)]' 
                : 'border-dark-600 text-dark-500 cursor-not-allowed opacity-50'
              }`}
            >
              <Crosshair className="w-4 h-4" /> Arm MITM
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
