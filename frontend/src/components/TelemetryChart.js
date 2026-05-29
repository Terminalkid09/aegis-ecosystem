import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { historyAPI } from '../services/api';

export default function TelemetryChart({ agentId }) {
  const [data, setData] = useState([]);

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const response = await historyAPI.getHistory(agentId);
        // Map backend data to recharts format
        const formatted = response.data.map(d => ({
            time: new Date(d.timestamp).toLocaleTimeString(),
            cpu: d.cpu_usage,
            ram: d.ram_usage
        })).reverse();
        setData(formatted);
      } catch (err) {
        console.error('Telemetry fetch error:', err);
      }
    };
    const interval = setInterval(fetchHistory, 5000);
    fetchHistory();
    return () => clearInterval(interval);
  }, [agentId]);

  return (
    <div className="h-64 w-full bg-slate-900 rounded p-4 border border-slate-700">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
          <XAxis dataKey="time" stroke="#94a3b8" fontSize={10} />
          <YAxis stroke="#94a3b8" fontSize={10} />
          <Tooltip contentStyle={{backgroundColor: '#1e293b', border: 'none'}} />
          <Line type="monotone" dataKey="cpu" stroke="#06b6d4" strokeWidth={2} dot={false} name="CPU %" />
          <Line type="monotone" dataKey="ram" stroke="#a855f7" strokeWidth={2} dot={false} name="RAM %" />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
