import React, { useEffect, useState } from 'react';
import { createClient } from '@supabase/supabase-js';
import { Shield, AlertTriangle, Activity, Database } from 'lucide-react';

const SUPABASE_URL = "https://qvjbxeoupprtjfnosisl.supabase.co";
const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL;
const SUPABASE_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY; 

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

export default function App() {
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState({ total: 0, highRisk: 0, mediumRisk: 0 });

  useEffect(() => {
    const fetchInitialLogs = async () => {
      const { data, error } = await supabase
        .from('packet_logs')
        .select('*')
        .order('id', { ascending: false })
        .limit(50);
      
      if (!error && data) {
        setLogs(data);
        calculateStats(data);
      } else if (error) {
        console.error("Error fetching initial logs:", error);
      }
    };

    fetchInitialLogs();

    const realtimeChannel = supabase
      .channel('packet-stream')
      .on(
        'postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'packet_logs' },
        (payload) => {
          setLogs((prevLogs) => {
            const updatedLogs = [payload.new, ...prevLogs.slice(0, 49)];
            calculateStats(updatedLogs);
            return updatedLogs;
          });
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(realtimeChannel);
    };
  }, []);

  const calculateStats = (currentLogs) => {
    const total = currentLogs.length;
    const highRisk = currentLogs.filter(l => l.risk_level === 'High').length;
    const mediumRisk = currentLogs.filter(l => l.risk_level === 'Medium').length;
    setStats({ total, highRisk, mediumRisk });
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 font-mono">
      {/* HEADER BAR */}
      <header className="border-b border-slate-800 pb-4 mb-6 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="w-8 h-8 text-emerald-400 animate-pulse" />
          <div>
            <h1 className="text-xl font-bold tracking-wider text-emerald-400">REALTIME-IDPS</h1>
            <p className="text-xs text-slate-400">Intrusion Detection & Prevention Node</p>
          </div>
        </div>
        <div className="flex items-center gap-2 bg-emerald-950/40 border border-emerald-800 text-emerald-400 px-3 py-1 rounded text-xs">
          <Activity className="w-4 h-4 animate-spin" /> Live Pipeline Connected
        </div>
      </header>

      {/* METRIC CARDS GRID */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="bg-slate-900 border border-slate-800 p-4 rounded flex items-center justify-between">
          <div>
            <p className="text-xs text-slate-400 uppercase font-semibold">Packets Analyzed</p>
            <h3 className="text-2xl font-bold text-white mt-1">{stats.total}</h3>
          </div>
          <Database className="w-8 h-8 text-sky-400" />
        </div>

        <div className="bg-slate-900 border border-slate-800 p-4 rounded flex items-center justify-between">
          <div>
            <p className="text-xs text-slate-400 uppercase font-semibold">Medium Alerts</p>
            <h3 className="text-2xl font-bold text-amber-500 mt-1">{stats.mediumRisk}</h3>
          </div>
          <AlertTriangle className="w-8 h-8 text-amber-500" />
        </div>

        <div className="bg-slate-900 border border-slate-800 p-4 rounded flex items-center justify-between">
          <div>
            <p className="text-xs text-slate-400 uppercase font-semibold">Critical Threats</p>
            <h3 className="text-2xl font-bold text-rose-500 mt-1">{stats.highRisk}</h3>
          </div>
          <AlertTriangle className="w-8 h-8 text-rose-500 animate-bounce" />
        </div>
      </div>

      {/* REAL-TIME LOG STREAM TABLE */}
      <div className="bg-slate-900 border border-slate-800 rounded overflow-hidden">
        <div className="bg-slate-800/50 px-4 py-3 border-b border-slate-700 text-xs font-bold text-slate-300 tracking-wider">
          LIVE SECURITY INGESTION STREAM
        </div>
        <div className="overflow-x-auto max-h-[60vh]">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-slate-900/50 text-slate-400 text-xs uppercase border-b border-slate-800">
                <th className="p-3">Risk Level</th>
                <th className="p-3">Classification</th>
                <th className="p-3">Source IP</th>
                <th className="p-3">Destination IP</th>
                <th className="p-3">Protocol</th>
                <th className="p-3">Length</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-sm">
              {logs.length === 0 ? (
                <tr>
                  <td colSpan="6" className="p-8 text-center text-slate-500 text-xs">
                    Waiting for network packets from backend sniffer node...
                  </td>
                </tr>
              ) : (
                logs.map((log, index) => (
                  <tr key={log.id || index} className="hover:bg-slate-800/30 transition-colors">
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                        log.risk_level === 'High' ? 'bg-rose-950 text-rose-400 border border-rose-800' :
                        log.risk_level === 'Medium' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                        'bg-emerald-950 text-emerald-400 border border-emerald-800'
                      }`}>
                        {log.risk_level}
                      </span>
                    </td>
                    <td className="p-3 font-semibold text-slate-200">{log.attack_type}</td>
                    <td className="p-3 text-sky-400">{log.source_ip}</td>
                    <td className="p-3 text-slate-400">{log.destination_ip}</td>
                    <td className="p-3"><span className="text-purple-400 text-xs font-bold">{log.protocol}</span></td>
                    <td className="p-3 text-slate-400 text-xs">{log.packet_size} bytes</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}