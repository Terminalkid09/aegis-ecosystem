import React, { useEffect, useRef } from 'react';
import uPlot from 'uplot';
import 'uplot/dist/uPlot.min.css';

export default function TelemetryChart({ data, darkMode }) {
  const chartRef = useRef(null);
  const containerRef = useRef(null);
  const uplotRef = useRef(null);

  useEffect(() => {
    if (!data || data.length === 0) {
      if (uplotRef.current) {
        uplotRef.current.destroy();
        uplotRef.current = null;
      }
      return () => {};
    }

    console.log('[TelemetryChart] Rendering with', data.length, 'data points, first:', data[0]);
    const timestamps = data.map(d => new Date(d.time).getTime() / 1000);
    const cpuData = data.map(d => d.cpu ?? 0);
    const ramData = data.map(d => d.ram ?? 0);

    const opts = {
      width: containerRef.current?.clientWidth || 800,
      height: 320,
      cursor: {
        show: true,
        drag: { x: true, y: true },
        bind: {
          dblclick: (u) => { u.setScale('x', u.series[0].scale || 'x', { min: null, max: null }); },
        },
      },
      select: {
        show: true,
        left: 0,
        top: 0,
        width: 0,
        height: 0,
        over: true,
      },
      axes: [
        {
          stroke: darkMode ? '#94a3b8' : '#64748b',
          grid: { stroke: darkMode ? '#334155' : '#e2e8f0', width: 1 },
          ticks: { stroke: 'transparent' },
          font: '10px monospace',
          values: (self, ticks) => ticks.map(v => {
            const d = new Date(v * 1000);
            return d.toLocaleTimeString();
          }),
        },
        {
          stroke: darkMode ? '#94a3b8' : '#64748b',
          grid: { stroke: darkMode ? '#334155' : '#e2e8f0', width: 1 },
          ticks: { stroke: 'transparent' },
          font: '10px monospace',
          size: 50,
          label: '%',
        },
      ],
      series: [
        {},
        {
          label: 'CPU',
          stroke: '#06b6d4',
          fill: 'rgba(6,182,212,0.08)',
          width: 2,
          points: { show: false },
          value: (self, v) => v ? v.toFixed(1) + '%' : '-',
        },
        {
          label: 'RAM',
          stroke: '#a855f7',
          fill: 'rgba(168,85,247,0.08)',
          width: 2,
          points: { show: false },
          value: (self, v) => v ? v.toFixed(1) + '%' : '-',
        },
      ],
      legend: { show: true, live: true },
    };

    const uplotData = [timestamps, cpuData, ramData];

    if (uplotRef.current) {
      uplotRef.current.setData(uplotData);
    } else {
      uplotRef.current = new uPlot(opts, uplotData, containerRef.current);
    }

    return () => {
      if (uplotRef.current) {
        uplotRef.current.destroy();
        uplotRef.current = null;
      }
    };
  }, [data, darkMode]);

  useEffect(() => {
    const handleResize = () => {
      if (uplotRef.current && containerRef.current) {
        uplotRef.current.setSize({ width: containerRef.current.clientWidth, height: 320 });
      }
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  const noData = !data || data.length === 0;

  if (noData) {
    return (
      <div className="flex flex-col items-center justify-center h-80 text-slate-500 gap-2">
        <div className="text-2xl font-mono opacity-30">~_~</div>
        <p className="italic text-sm">Waiting for NodeTrace telemetry data...</p>
        <p className="text-xs opacity-60">Agents send CPU/RAM metrics every 60 seconds</p>
      </div>
    );
  }

  return (
    <div ref={containerRef} style={{ width: '100%', height: '320px' }} />
  );
}
